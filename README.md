# BunnyWAF

BunnyWAF is a lightweight, playground-level, signature-based Web Application Firewall (WAF) - detect only
<br/><br/>
BunnyWAF focuses on detecting:<br/>
SQL Injection (SQLi)<br/>
Cross-Site Scripting (XSS)<br/><br/>

## Supported Web Server
It can read access logs from:<br/>
Apache<br/>
Nginx<br/>
IIS<br/>

### Apache and Nginx Log Format
The current Apache/Nginx parser expects an access log that follows the combined access-log format.
### IIS Log Format
IIS uses the W3C Extended Log File Format. BunnyWAF reads the IIS #Fields: header to determine the fields in each log entry.

The detection signatures are stored separately, making them easy to add or modify without changing the main program.

### Example alert:
15:20:53 ALERT BunnyWAF: host=192.168.1.51 method=GET request=/product?id=1%20UNION%20SELECT%20username%20FROM%20users type=SQLI

### Apache LogFormat used in playground
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined<br/>
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
