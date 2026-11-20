import logging
import os
import subprocess
from contextvars import ContextVar
from typing import List, Optional

from fastapi import HTTPException


command_audit = ContextVar("command_audit", default=None)


def run_command(cmd_list: List[str], input_text: Optional[str] = None) -> str:
    """Run a shell command securely and return output."""
    audit = command_audit.get()
    details = {"executable": os.path.basename(cmd_list[0])}
    status = "error"
    try:
        result = subprocess.run(
            cmd_list,
            input=input_text,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        status = "success"
        details["exit_code"] = result.returncode
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        details["exit_code"] = exc.returncode
        logging.error("%s exited with status %s", cmd_list[0], exc.returncode)
        raise HTTPException(status_code=500, detail=f"System Error: {exc.stderr}")
    except OSError as exc:
        details["errno"] = exc.errno
        raise
    finally:
        if audit is not None:
            audit("command", "run_command", details=details, status=status)
