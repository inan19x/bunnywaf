import os
import re
import time
from datetime import datetime
from urllib.parse import unquote
from configparser import ConfigParser
from dataclasses import dataclass


CONFIG_FILE = "config/bunny.conf"
POLL_INTERVAL = 0.5


@dataclass
class HttpRequest:
    """Normalized HTTP request."""

    host: str
    timestamp: str
    method: str
    request: str


def load_config(filename):
    """Load BunnyWAF configuration."""

    config = ConfigParser()

    if not config.read(filename):
        raise ValueError(
            f"Configuration file not found: {filename}"
        )

    if "general" not in config:
        raise ValueError(
            "Missing [general] section in configuration"
        )

    general = config["general"]

    log_type = general.get(
        "log_type",
        "apache",
    ).lower()

    access_log = general.get("access_log")
    signature_file = general.get("signature_file")
    alert_log = general.get("alert_log")

    supported_types = (
        "apache",
        "nginx",
        "iis",
    )

    if log_type not in supported_types:
        raise ValueError(
            f"Unsupported log_type: {log_type}. "
            f"Supported types: {', '.join(supported_types)}"
        )

    if not access_log:
        raise ValueError(
            "access_log is not configured"
        )

    if not signature_file:
        raise ValueError(
            "signature_file is not configured"
        )

    if not alert_log:
        raise ValueError(
            "alert_log is not configured"
        )

    return {
        "log_type": log_type,
        "access_log": access_log,
        "signature_file": signature_file,
        "alert_log": alert_log,
    }


def load_signatures(filename):
    """
    Load SQLI and XSS signatures.

    Example:

    [SQLI]
    UNION SELECT
    SLEEP(

    [XSS]
    <SCRIPT
    JAVASCRIPT:
    """

    signatures = {
        "SQLI": [],
        "XSS": [],
    }

    current_type = None

    try:
        with open(
            filename,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if (
                    line.startswith("[")
                    and line.endswith("]")
                ):
                    section = line[1:-1].upper()

                    if section in signatures:
                        current_type = section
                    else:
                        current_type = None

                    continue

                if current_type:
                    signatures[current_type].append(
                        line.upper()
                    )

    except FileNotFoundError:
        raise ValueError(
            f"Signature file not found: {filename}"
        )

    return signatures


def parse_apache_nginx_line(line):
    """
    Parse Apache/Nginx combined access log.

    Example:

    192.168.1.1 - - [10/Sep/2026:18:24:01 +0000]
    "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
    """

    pattern = (
        r'^(\S+)\s+'
        r'\S+\s+'
        r'\S+\s+'
        r'\[([^\]]+)\]\s+'
        r'"(\S+)\s+(\S+)\s+[^"]+"'
    )

    match = re.match(
        pattern,
        line,
    )

    if not match:
        return None

    return HttpRequest(
        host=match.group(1),
        timestamp=match.group(2),
        method=match.group(3),
        request=match.group(4),
    )


def parse_iis_line(line, fields):
    """
    Parse an IIS W3C log line using the #Fields definition.

    Required fields:

        date
        time
        cs-method
        cs-uri-stem

    Optional:

        cs-uri-query
        c-ip
        s-ip
    """

    if not fields:
        return None

    values = line.split()

    if len(values) < len(fields):
        return None

    data = dict(
        zip(
            fields,
            values,
        )
    )

    required_fields = {
        "date",
        "time",
        "cs-method",
        "cs-uri-stem",
    }

    if not required_fields.issubset(data):
        return None

    date = data["date"]
    time_value = data["time"]

    method = data["cs-method"]
    uri_stem = data["cs-uri-stem"]

    # IIS uses "-" when there is no query string.
    uri_query = data.get(
        "cs-uri-query",
        "-",
    )

    if uri_query == "-":
        request = uri_stem
    else:
        request = (
            f"{uri_stem}?{uri_query}"
        )

    # c-ip is the client IP.
    # If it isn't logged, fall back to s-ip.
    host = data.get(
        "c-ip",
        data.get(
            "s-ip",
            "UNKNOWN",
        ),
    )

    return HttpRequest(
        host=host,
        timestamp=f"{date} {time_value}",
        method=method,
        request=request,
    )


def detect_attack(request, signatures):
    """
    Detect SQLI or XSS.

    URL-encoded requests are decoded before matching.
    """

    decoded_request = unquote(request)

    normalized_request = (
        decoded_request.upper()
    )

    for pattern in signatures["SQLI"]:
        if pattern in normalized_request:
            return "SQLI"

    for pattern in signatures["XSS"]:
        if pattern in normalized_request:
            return "XSS"

    return None


def format_time(timestamp):
    """Convert timestamp to HH:MM:SS."""

    formats = [
        "%d/%b/%Y:%H:%M:%S %z",  # Apache/Nginx
        "%Y-%m-%d %H:%M:%S",     # IIS
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(
                timestamp,
                fmt,
            )

            return dt.strftime(
                "%H:%M:%S"
            )

        except ValueError:
            continue

    return timestamp


def create_alert(entry, attack_type):
    """Create a BunnyWAF alert."""

    time_value = format_time(
        entry.timestamp
    )

    return (
        f"{time_value} ALERT BunnyWAF: "
        f"host={entry.host} "
        f"method={entry.method} "
        f"request={entry.request} "
        f"type={attack_type}"
    )


def write_alert(filename, alert):
    """Append an alert to BunnyWAF's log."""

    directory = os.path.dirname(
        filename
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    with open(
        filename,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            alert + "\n"
        )


def follow_log(
    filename,
    poll_interval=POLL_INTERVAL,
):
    """
    Existing log entries are ignored.

    BunnyWAF starts at the current end of the file and
    only yields lines appended after monitoring begins.

    Basic handling for log truncation/replacement is included.
    """

    while True:

        try:
            with open(
                filename,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as log:

                # Ignore everything already in the log.
                log.seek(
                    0,
                    os.SEEK_END,
                )

                inode = os.fstat(
                    log.fileno()
                ).st_ino

                while True:

                    line = log.readline()

                    if line:
                        yield line
                        continue

                    time.sleep(
                        poll_interval
                    )

                    # Check whether the file was
                    # truncated.
                    try:
                        current_size = os.path.getsize(
                            filename
                        )

                        current_position = log.tell()

                        if current_size < current_position:
                            # The file was truncated.
                            # Start following from its new beginning.
                            log.seek(
                                0,
                                os.SEEK_SET,
                            )

                            continue

                    except FileNotFoundError:
                        # The file may temporarily disappear
                        # during log rotation.
                        break

                    # Check whether the pathname now refers
                    # to a different file.
                    try:
                        current_inode = os.stat(
                            filename
                        ).st_ino

                        if current_inode != inode:
                            # Log rotation/replacement detected.
                            break

                    except FileNotFoundError:
                        break

        except FileNotFoundError:
            print(
                f"Error: access log not found: "
                f"{filename}"
            )

            time.sleep(
                poll_interval
            )

        except PermissionError:
            print(
                f"Error: permission denied: "
                f"{filename}"
            )

            time.sleep(
                poll_interval
            )

        except OSError as error:
            print(
                f"Error following access log: "
                f"{error}"
            )

            time.sleep(
                poll_interval
            )


def process_line(
    line,
    log_type,
    signatures,
    alert_log,
    iis_fields,
):
    """
    Process one access log line.

    Returns the updated IIS field mapping.
    """

    if log_type == "iis":

        if not iis_fields:

            iis_fields = [
                "date",
                "time",
                "s-ip",
                "cs-method",
                "cs-uri-stem",
                "cs-uri-query",
                "s-port",
                "cs-username",
                "c-ip",
                "cs(User-Agent)",
                "cs(Referer)",
                "sc-status",
                "sc-substatus",
                "sc-win32-status",
                "time-taken",
            ]

        if line.startswith("#Fields:"):

            fields_string = line[
                len("#Fields:"):
            ].strip()

            iis_fields = fields_string.split()

            return iis_fields

        # Ignore IIS comments and metadata.

        if line.startswith("#"):
            return iis_fields

        entry = parse_iis_line(
            line,
            iis_fields,
        )

    else:

        # Apache / Nginx

        entry = parse_apache_nginx_line(
            line
        )

    if not entry:
        return iis_fields

    attack_type = detect_attack(
        entry.request,
        signatures,
    )

    if not attack_type:
        return iis_fields

    alert = create_alert(
        entry,
        attack_type,
    )

    print(alert)

    write_alert(
        alert_log,
        alert,
    )

    return iis_fields



def scan_log(
    config,
    signatures,
):
    """
    Continuously monitor the configured access log.

    Existing entries are ignored.

    New entries are processed in real time.
    """

    access_log = config["access_log"]
    log_type = config["log_type"]
    alert_log = config["alert_log"]

    iis_fields = None

    print(
        f"BunnyWAF monitoring: {access_log}"
    )

    for line in follow_log(
        access_log
    ):

        iis_fields = process_line(
            line=line,
            log_type=log_type,
            signatures=signatures,
            alert_log=alert_log,
            iis_fields=iis_fields,
        )


def main():
    """BunnyWAF entry point."""

    try:
        config = load_config(
            CONFIG_FILE
        )

        signatures = load_signatures(
            config["signature_file"]
        )

        scan_log(
            config,
            signatures,
        )

    except KeyboardInterrupt:
        print(
            "\nBunnyWAF stopped."
        )

    except ValueError as error:
        print(
            f"BunnyWAF error: {error}"
        )


if __name__ == "__main__":
    main()

