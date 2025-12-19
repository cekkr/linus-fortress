import shutil
from typing import Optional

from fastapi import HTTPException

from fortress.system import run_command


def detect_firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    raise HTTPException(status_code=500, detail="No supported firewall backend detected (ufw or firewalld)")


def _build_firewalld_rich_rule(source: Optional[str], protocol: str, port: int, allow: bool) -> str:
    action = "accept" if allow else "drop"
    if source:
        return f'rule family="ipv4" source address="{source}" port protocol="{protocol}" port="{port}" {action}'
    return f'rule family="ipv4" port protocol="{protocol}" port="{port}" {action}'


def apply_firewall_rule(port: int, protocol: str, source: Optional[str], allow: bool) -> None:
    backend = detect_firewall_backend()
    if backend == "ufw":
        action_word = "allow" if allow else "deny"
        if source:
            base_cmd = ["ufw", action_word, "from", source, "to", "any", "port", str(port), "proto", protocol]
        else:
            base_cmd = ["ufw", action_word, f"{port}/{protocol}"]
        if not allow:
            if source:
                base_cmd = ["ufw", "--force", "delete", "allow", "from", source, "to", "any", "port", str(port), "proto", protocol]
            else:
                base_cmd = ["ufw", "--force", "delete", "allow", f"{port}/{protocol}"]
        run_command(base_cmd)
        run_command(["ufw", "reload"])
        return

    if backend == "firewalld":
        if source:
            rich_rule = _build_firewalld_rich_rule(source, protocol, port, allow)
            flag = "--add-rich-rule" if allow else "--remove-rich-rule"
            run_command(["firewall-cmd", "--permanent", flag, rich_rule])
        else:
            flag = "--add-port" if allow else "--remove-port"
            run_command(["firewall-cmd", "--permanent", flag, f"{port}/{protocol}"])
        run_command(["firewall-cmd", "--reload"])
        return

    raise HTTPException(status_code=500, detail=f"Unsupported firewall backend {backend}")
