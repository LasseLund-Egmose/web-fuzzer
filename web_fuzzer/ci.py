MATH = "123456789+13371337" # 136828126 is set as an interesting string
PREFIX_ESCAPE = {'', "'", '"'}
PREFIXES = {'', '|', '||', '&', '&&', ';'}
SUFFIXES = {'', '|', '&', "'", '"', ';', '//', '\\\\', '#'}
SUFFIX_BALANCE = {'', "echo '", 'echo "'}
COMMANDS = {f"{MATH}", f"echo $(({MATH}))", f"set /a {MATH}", "sleep 10", "$(sleep 10)", "timeout /t 10" }

def command_injection_fuzz(args):
    for prefix_escape in PREFIX_ESCAPE:
        for prefix in PREFIXES:
            for suffix in SUFFIXES:
                for suffix_balance in SUFFIX_BALANCE:
                    for command in COMMANDS:
                        yield f"{prefix_escape}{prefix}{command}{suffix}{suffix_balance}".encode()