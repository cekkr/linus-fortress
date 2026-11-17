import logging
import subprocess
from typing import List

from fastapi import HTTPException


def run_command(cmd_list: List[str]) -> str:
    """Run a shell command securely and return output."""
    try:
        result = subprocess.run(
            cmd_list,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        logging.error("%s exited with status %s", cmd_list[0], exc.returncode)
        raise HTTPException(status_code=500, detail=f"System Error: {exc.stderr}")
