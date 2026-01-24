import json
import os
import re
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from fortress.system import run_command


def detect_firewall_backend() -> str:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    raise HTTPException(status_code=500, detail="No supported firewall backend detected (ufw or firewalld)")

def _iptables_available() -> bool:
    return shutil.which("iptables") is not None

def _connlimit_rule_args(protocol: str, port: int, limit: int) -> List[str]:
    return [
        "-p",
        protocol,
        "--dport",
        str(port),
        "-m",
        "connlimit",
        "--connlimit-above",
        str(limit),
        "--connlimit-saddr",
        "--connlimit-mask",
        "32",
        "-j",
        "REJECT",
        "--reject-with",
        "tcp-reset",
    ]

def _iptables_rule_exists(rule_args: List[str]) -> bool:
    try:
        run_command(["iptables", "-C", "INPUT"] + rule_args)
        return True
    except HTTPException:
        return False

def _apply_connlimit_rule(port: int, limit: int) -> None:
    rule_args = _connlimit_rule_args("tcp", port, limit)
    if _iptables_rule_exists(rule_args):
        return
    run_command(["iptables", "-I", "INPUT"] + rule_args)

def _remove_connlimit_rule(port: int, limit: int) -> None:
    rule_args = _connlimit_rule_args("tcp", port, limit)
    if not _iptables_rule_exists(rule_args):
        return
    run_command(["iptables", "-D", "INPUT"] + rule_args)


def _build_firewalld_rich_rule(source: Optional[str], protocol: str, port: int, allow: bool, limit: Optional[str] = None) -> str:
    action = "accept" if allow else "drop"
    if source:
        base = f'rule family="ipv4" source address="{source}" port protocol="{protocol}" port="{port}" {action}'
    else:
        base = f'rule family="ipv4" port protocol="{protocol}" port="{port}" {action}'
    if limit:
        return f'{base} limit value="{limit}"'
    return base


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


def _parse_ufw_status(output: str) -> Tuple[bool, Dict[str, str]]:
    active = False
    defaults: Dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Status:"):
            active = "active" in line.lower()
        if line.startswith("Default:"):
            parts = line.replace("Default:", "").split(",")
            for part in parts:
                chunk = part.strip()
                if "incoming" in chunk:
                    defaults["inbound"] = chunk.split()[0]
                if "outgoing" in chunk:
                    defaults["outbound"] = chunk.split()[0]
    return active, defaults


def _parse_ufw_rules(output: str) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    started = False
    for line in output.splitlines():
        if not line.strip():
            continue
        if line.startswith("To"):
            started = True
            continue
        if line.startswith("--"):
            continue
        if not started:
            continue
        parts = re.split(r"\s{2,}", line.strip())
        if len(parts) < 2:
            continue
        to_field = parts[0]
        action_field = parts[1]
        source = parts[2] if len(parts) > 2 else None
        if "(v6)" in to_field or (source and "(v6)" in source):
            continue
        if to_field.lower().startswith("anywhere"):
            continue
        protocol = "tcp"
        port_str = to_field
        if "/" in to_field:
            port_str, protocol = to_field.split("/", 1)
        try:
            port = int(port_str)
        except ValueError:
            continue
        action_tokens = action_field.split()
        action = action_tokens[0].lower()
        direction = "in"
        if len(action_tokens) > 1:
            direction = action_tokens[1].lower()
        rules.append(
            {
                "port": port,
                "protocol": protocol.lower(),
                "source": None if source and source.lower().startswith("anywhere") else source,
                "action": "allow" if action == "allow" else "deny",
                "direction": direction,
            }
        )
    return rules


def _parse_firewalld_ports(output: str) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for item in output.split():
        if "/" not in item:
            continue
        port_str, protocol = item.split("/", 1)
        try:
            port = int(port_str)
        except ValueError:
            continue
        rules.append(
            {
                "port": port,
                "protocol": protocol.lower(),
                "source": None,
                "action": "allow",
                "direction": "in",
            }
        )
    return rules


def _parse_firewalld_rich_rules(output: str) -> List[Dict[str, Any]]:
    rules: List[Dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("rule"):
            continue
        source_match = re.search(r'source address="([^"]+)"', line)
        port_match = re.search(r'port protocol="([^"]+)" port="([^"]+)"', line)
        action = "allow" if "accept" in line else "deny" if "drop" in line else None
        if not port_match or not action:
            continue
        protocol = port_match.group(1).lower()
        try:
            port = int(port_match.group(2))
        except ValueError:
            continue
        rules.append(
            {
                "port": port,
                "protocol": protocol,
                "source": source_match.group(1) if source_match else None,
                "action": action,
                "direction": "in",
            }
        )
    return rules


def get_firewall_status() -> Dict[str, Any]:
    backend = detect_firewall_backend()
    rules = list_firewall_rules()
    if backend == "ufw":
        output = run_command(["ufw", "status", "verbose"])
        active, defaults = _parse_ufw_status(output)
        return {
            "backend": backend,
            "active": active,
            "default_inbound": defaults.get("inbound"),
            "default_outbound": defaults.get("outbound"),
            "rules_count": len(rules),
            "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    state = run_command(["firewall-cmd", "--state"])
    active = "running" in state.lower()
    return {
        "backend": backend,
        "active": active,
        "default_inbound": "unknown",
        "default_outbound": "unknown",
        "rules_count": len(rules),
        "last_updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def list_firewall_rules() -> List[Dict[str, Any]]:
    backend = detect_firewall_backend()
    if backend == "ufw":
        output = run_command(["ufw", "status", "verbose"])
        return _parse_ufw_rules(output)
    ports = run_command(["firewall-cmd", "--list-ports"])
    rules = _parse_firewalld_ports(ports)
    rich_rules = run_command(["firewall-cmd", "--list-rich-rules"])
    rules.extend(_parse_firewalld_rich_rules(rich_rules))
    return rules


def _build_rule_key(rule: Dict[str, Any]) -> str:
    return ":".join(
        [
            rule.get("action", "allow"),
            rule.get("direction", "in"),
            str(rule.get("port")),
            rule.get("protocol", "tcp"),
            rule.get("source") or "any",
        ]
    )


def _apply_single_rule(rule: Dict[str, Any], allow: bool) -> None:
    backend = detect_firewall_backend()
    port = int(rule["port"])
    protocol = rule.get("protocol", "tcp")
    source = rule.get("source")
    action = rule.get("action", "allow")
    direction = rule.get("direction", "in")
    if backend == "ufw":
        action_word = "allow" if action == "allow" else "deny"
        if direction == "out":
            base_cmd = ["ufw", action_word, "out", f"{port}/{protocol}"]
        elif source:
            base_cmd = ["ufw", action_word, "from", source, "to", "any", "port", str(port), "proto", protocol]
        else:
            base_cmd = ["ufw", action_word, f"{port}/{protocol}"]
        if not allow:
            if direction == "out":
                base_cmd = ["ufw", "--force", "delete", action_word, "out", f"{port}/{protocol}"]
            elif source:
                base_cmd = ["ufw", "--force", "delete", action_word, "from", source, "to", "any", "port", str(port), "proto", protocol]
            else:
                base_cmd = ["ufw", "--force", "delete", action_word, f"{port}/{protocol}"]
        run_command(base_cmd)
        run_command(["ufw", "reload"])
        return
    allow_rule = action == "allow"
    if allow:
        if source or action != "allow":
            rich_rule = _build_firewalld_rich_rule(source, protocol, port, allow_rule)
            run_command(["firewall-cmd", "--permanent", "--add-rich-rule", rich_rule])
        else:
            run_command(["firewall-cmd", "--permanent", "--add-port", f"{port}/{protocol}"])
    else:
        if source or action != "allow":
            rich_rule = _build_firewalld_rich_rule(source, protocol, port, allow_rule)
            run_command(["firewall-cmd", "--permanent", "--remove-rich-rule", rich_rule])
        else:
            run_command(["firewall-cmd", "--permanent", "--remove-port", f"{port}/{protocol}"])
    run_command(["firewall-cmd", "--reload"])


def _build_rollback_id() -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"fw-{stamp}"


def apply_firewall_rules(
    rules: List[Dict[str, Any]],
    mode: str,
    dry_run: bool,
    rollback_dir: str,
) -> Dict[str, Any]:
    existing = list_firewall_rules()
    existing_keys = {_build_rule_key(rule) for rule in existing}
    desired_keys = {_build_rule_key(rule) for rule in rules}
    to_add = [rule for rule in rules if _build_rule_key(rule) not in existing_keys]
    to_remove: List[Dict[str, Any]] = []
    if mode == "replace":
        to_remove = [rule for rule in existing if _build_rule_key(rule) not in desired_keys]
    changes: List[Dict[str, Any]] = []
    if not dry_run:
        for rule in to_add:
            _apply_single_rule(rule, allow=True)
            changes.append({"action": "add", "rule": rule})
        for rule in to_remove:
            _apply_single_rule(rule, allow=False)
            changes.append({"action": "remove", "rule": rule})
    rollback_id = None
    if changes and not dry_run:
        os.makedirs(rollback_dir, exist_ok=True)
        rollback_id = _build_rollback_id()
        path = os.path.join(rollback_dir, f"{rollback_id}.json")
        with open(path, "w") as fh:
            json.dump({"rollback_id": rollback_id, "changes": changes, "created_at": time.time()}, fh, indent=2)
    return {
        "applied": len(to_add) + len(to_remove),
        "skipped": len(rules) - len(to_add),
        "rollback_id": rollback_id,
        "dry_run": dry_run,
    }


def rollback_firewall_rules(rollback_path: str, dry_run: bool) -> None:
    if not os.path.exists(rollback_path):
        raise HTTPException(status_code=404, detail="Rollback id not found")
    with open(rollback_path, "r") as fh:
        payload = json.load(fh)
    for change in payload.get("changes", []):
        rule = change.get("rule")
        if not rule:
            continue
        if dry_run:
            continue
        if change.get("action") == "add":
            _apply_single_rule(rule, allow=False)
        elif change.get("action") == "remove":
            _apply_single_rule(rule, allow=True)


def get_ddos_policy(policy_path: str) -> Dict[str, Any]:
    if not os.path.exists(policy_path):
        return {"enabled": False, "profile": "baseline"}
    with open(policy_path, "r") as fh:
        return json.load(fh)


def update_ddos_policy(policy: Dict[str, Any], policy_path: str) -> Dict[str, Any]:
    ensure_dir = os.path.dirname(policy_path)
    if ensure_dir:
        os.makedirs(ensure_dir, exist_ok=True)
    with open(policy_path, "w") as fh:
        json.dump(policy, fh, indent=2)
    return policy


def apply_ddos_policy(policy: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    backend = detect_firewall_backend()
    warnings: List[str] = []
    effective_rules: List[str] = []
    if not policy.get("enabled"):
        return effective_rules, warnings
    ports = policy.get("ports") or [80, 443]
    protocol = policy.get("protocol", "tcp")
    allowlist = policy.get("allowlist") or []
    denylist = policy.get("denylist") or []
    rate = policy.get("rate_limit_per_sec")
    burst = policy.get("burst")
    limit_value = None
    if rate:
        limit_value = f"{rate}/s"
        if burst:
            limit_value = f"{rate}/s"
    for source in allowlist:
        for port in ports:
            _apply_single_rule(
                {"port": port, "protocol": protocol, "source": source, "action": "allow", "direction": "in"},
                allow=True,
            )
            effective_rules.append(f"allow {source} {port}/{protocol}")
    for source in denylist:
        for port in ports:
            _apply_single_rule(
                {"port": port, "protocol": protocol, "source": source, "action": "deny", "direction": "in"},
                allow=True,
            )
            effective_rules.append(f"deny {source} {port}/{protocol}")
    if rate:
        if backend == "ufw":
            for port in ports:
                run_command(["ufw", "limit", f"{port}/{protocol}"])
                run_command(["ufw", "reload"])
                effective_rules.append(f"limit {port}/{protocol}")
        elif backend == "firewalld":
            for port in ports:
                rich_rule = _build_firewalld_rich_rule(None, protocol, port, allow=True, limit=limit_value)
                run_command(["firewall-cmd", "--permanent", "--add-rich-rule", rich_rule])
                run_command(["firewall-cmd", "--reload"])
                effective_rules.append(f"limit {port}/{protocol} {limit_value}")
    conn_limit = policy.get("conn_limit")
    if conn_limit:
        if protocol != "tcp":
            warnings.append("conn_limit only supported for tcp")
        elif not _iptables_available():
            warnings.append("conn_limit requires iptables")
        else:
            if allowlist:
                warnings.append("conn_limit ignores allowlist ordering")
            for port in ports:
                _apply_connlimit_rule(int(port), int(conn_limit))
                effective_rules.append(f"connlimit {port}/{protocol} {conn_limit}")
    return effective_rules, warnings


def remove_ddos_policy(policy: Dict[str, Any]) -> List[str]:
    if not policy.get("enabled"):
        return []
    removed: List[str] = []
    ports = policy.get("ports") or [80, 443]
    protocol = policy.get("protocol", "tcp")
    allowlist = policy.get("allowlist") or []
    denylist = policy.get("denylist") or []
    rate = policy.get("rate_limit_per_sec")
    for source in allowlist:
        for port in ports:
            _apply_single_rule(
                {"port": port, "protocol": protocol, "source": source, "action": "allow", "direction": "in"},
                allow=False,
            )
            removed.append(f"allow {source} {port}/{protocol}")
    for source in denylist:
        for port in ports:
            _apply_single_rule(
                {"port": port, "protocol": protocol, "source": source, "action": "deny", "direction": "in"},
                allow=False,
            )
            removed.append(f"deny {source} {port}/{protocol}")
    if rate:
        backend = detect_firewall_backend()
        for port in ports:
            if backend == "ufw":
                run_command(["ufw", "--force", "delete", "limit", f"{port}/{protocol}"])
                run_command(["ufw", "reload"])
                removed.append(f"limit {port}/{protocol}")
            elif backend == "firewalld":
                limit_value = f"{rate}/s"
                rich_rule = _build_firewalld_rich_rule(None, protocol, port, allow=True, limit=limit_value)
                run_command(["firewall-cmd", "--permanent", "--remove-rich-rule", rich_rule])
                run_command(["firewall-cmd", "--reload"])
                removed.append(f"limit {port}/{protocol} {limit_value}")
    conn_limit = policy.get("conn_limit")
    if conn_limit and protocol == "tcp" and _iptables_available():
        for port in ports:
            _remove_connlimit_rule(int(port), int(conn_limit))
            removed.append(f"connlimit {port}/{protocol} {conn_limit}")
    return removed
