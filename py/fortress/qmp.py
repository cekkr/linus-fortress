"""Private QEMU monitor client for managed snapshot operations."""

import hashlib
import json
import logging
import os
import socket
import time
from contextlib import closing

from fastapi import HTTPException


DISK_NODE = "fortress-disk"
SNAPSHOT_COMMANDS = {"create": "snapshot-save", "restore": "snapshot-load", "delete": "snapshot-delete"}
MAX_QMP_FRAME_BYTES = 4 * 1024 * 1024
QMP_CONNECT_SECONDS = 5
QMP_JOB_SECONDS = 180


class _QMP:
    def __init__(self, connection, stream):
        self.connection = connection
        self.stream = stream
        self.deadline = time.monotonic() + QMP_CONNECT_SECONDS
        self.sequence = 0

    def _set_timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.connection.settimeout(remaining)

    def read(self):
        self._set_timeout()
        line = self.stream.readline(MAX_QMP_FRAME_BYTES + 1)
        if not line.endswith(b"\n") or len(line) > MAX_QMP_FRAME_BYTES:
            raise ValueError("Incomplete or oversized QMP frame")
        message = json.loads(line)
        if not isinstance(message, dict):
            raise ValueError("Invalid QMP frame")
        return message

    def call(self, command, arguments=None):
        self.sequence += 1
        message = {"execute": command, "id": self.sequence}
        if arguments is not None:
            message["arguments"] = arguments
        self._set_timeout()
        self.connection.sendall(json.dumps(message).encode("utf-8") + b"\n")
        while True:
            response = self.read()
            if response.get("id") != self.sequence:
                continue  # asynchronous QMP events have no request ID
            if "return" in response:
                return response["return"]
            if response.get("error", {}).get("class") == "CommandNotFound":
                raise HTTPException(409, "This QEMU monitor does not support live snapshots")
            raise HTTPException(409, f"QEMU rejected {command}")


def _require_managed_disk(qmp, vm_name, disk_path):
    if qmp.call("query-name").get("name") != vm_name:
        raise HTTPException(409, "The QEMU monitor belongs to a different VM")
    disks = [
        disk["inserted"] for disk in qmp.call("query-block")
        if disk.get("inserted") and not disk["inserted"].get("ro")
    ]
    if len(disks) != 1 or (
        disks[0].get("node-name") != DISK_NODE
        or os.path.realpath(disks[0].get("file") or "") != disk_path
        or disks[0].get("drv") != "qcow2"
    ):
        raise HTTPException(409, "Live snapshots require the VM's single managed writable QCOW2 disk")


def _existing_snapshot(qmp, snapshot_name):
    for node in qmp.call("query-named-block-nodes"):
        if node.get("node-name") == DISK_NODE:
            return next(
                (snapshot for snapshot in node.get("image", {}).get("snapshots", []) if snapshot["name"] == snapshot_name),
                None,
            )
    raise HTTPException(409, "The managed QEMU disk is unavailable")


def _run_job(qmp, action, snapshot_name):
    command = SNAPSHOT_COMMANDS[action]
    digest = hashlib.sha256(snapshot_name.encode("utf-8")).hexdigest()[:24]
    job_id = f"fortress-{action}-{digest}"
    jobs = qmp.call("query-jobs")
    if any(job["id"] != job_id and job["status"] != "concluded" for job in jobs):
        raise HTTPException(409, "Wait for the active QEMU job to finish")
    job = next((job for job in jobs if job["id"] == job_id), None)
    if job is None:
        snapshot = _existing_snapshot(qmp, snapshot_name)
        if action == "create" and snapshot:
            # Recover an image snapshot whose registry write did not complete.
            if snapshot.get("vm-state-size", 0) > 0:
                return
            raise HTTPException(409, "A disk-only QEMU snapshot already has this name")
        if action == "delete" and snapshot is None:
            return  # A retry can finish removing the stale registry entry.
        if action == "restore" and not (snapshot and snapshot.get("vm-state-size", 0) > 0):
            raise HTTPException(409, "This snapshot does not contain live VM state")
        arguments = {"job-id": job_id, "tag": snapshot_name, "devices": [DISK_NODE]}
        if action != "delete":
            arguments["vmstate"] = DISK_NODE
        qmp.call(command, arguments)

    while job is None or job["status"] != "concluded":
        job = next((job for job in qmp.call("query-jobs") if job["id"] == job_id), None)
        if job is None:
            raise HTTPException(502, "QEMU did not report the live snapshot job outcome")
        if job["status"] != "concluded":
            time.sleep(0.15)
    try:
        qmp.call("job-dismiss", {"id": job_id})
    except (HTTPException, OSError, ValueError):
        logging.warning("Could not dismiss the concluded QEMU snapshot job %s", job_id)
    if job.get("error"):
        raise HTTPException(409, f"QEMU could not {action} the live snapshot")


def run_snapshot(socket_path: str, vm_name: str, disk_path: str, action: str, snapshot_name: str) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(QMP_CONNECT_SECONDS)
        try:
            connection.connect(socket_path)
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            raise HTTPException(409, "Start the VM with Fortress before using live snapshots") from exc
        except OSError as exc:
            raise HTTPException(502, "Could not connect to the private QEMU monitor") from exc
        try:
            with closing(connection.makefile("rb")) as stream:
                qmp = _QMP(connection, stream)
                if "QMP" not in qmp.read():
                    raise ValueError("Missing QMP greeting")
                qmp.call("qmp_capabilities")
                _require_managed_disk(qmp, vm_name, disk_path)
                qmp.deadline = time.monotonic() + QMP_JOB_SECONDS
                _run_job(qmp, action, snapshot_name)
        except (TimeoutError, socket.timeout) as exc:
            raise HTTPException(504, "QEMU snapshot request timed out. Retry the same operation to check its outcome.") from exc
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise HTTPException(502, "Could not determine the live snapshot outcome from QEMU") from exc
