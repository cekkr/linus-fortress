"""Run a host-wide scheduled renewal and record its result without API credentials."""

import logging
import os
from uuid import uuid4

from fastapi import HTTPException

from fortress.audit import CommandLogger
from fortress.routing import reload_nginx, test_nginx_config
from fortress.system import command_audit
from fortress.tls import renew_letsencrypt


def run_scheduled_renewal(logger: CommandLogger) -> int:
    run_id = uuid4().hex

    def log(category, action, **fields):
        return logger.log("systemd", "fortress-tls-renewal.service", category, action, request_id=run_id, **fields)

    failed_steps = []

    def attempt(step, operation):
        try:
            operation()
        except (HTTPException, OSError):
            failed_steps.append(step)
            return False
        return True

    context = command_audit.set(log)
    try:
        attempt("certbot", renew_letsencrypt)
        # Certbot can renew some certificates before returning an error. Reload
        # even then, and retry a prior reload failure when the next run is a no-op.
        if attempt("nginx_config", test_nginx_config):
            attempt("nginx_reload", reload_nginx)
    finally:
        command_audit.reset(context)

    recorded = log(
        "internal", "tls_renew_scheduled", status="error" if failed_steps else "success",
        details={"failed_steps": failed_steps},
    )
    if not recorded:
        logging.error("Could not record scheduled TLS renewal outcome (run %s)", run_id)
    if failed_steps:
        logging.error("Scheduled TLS renewal failed in %s (run %s)", ", ".join(failed_steps), run_id)
    elif recorded:
        logging.info("Scheduled TLS renewal completed (run %s)", run_id)
    return int(bool(failed_steps) or not recorded)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(run_scheduled_renewal(CommandLogger(os.environ.get(
        "FORTRESS_COMMAND_LOG_DB", "/var/lib/fortress/command_log.db"
    ))))
