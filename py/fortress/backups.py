"""Authenticated, versioned backup archives shared by the API and CLI."""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import tempfile
from contextlib import contextmanager
from itertools import count
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


MAGIC = b"FORTRESS-BACKUP\x02"
CHUNK_BYTES = 1024 * 1024
SALT_BYTES = 16
TAG_BYTES = 16
LENGTH = struct.Struct(">I")
DEFAULT_BACKUP_PASSWORD = "CHANGE_THIS_TO_YOUR_STRONG_BACKUP_PASSWORD"


class InvalidBackup(ValueError):
    pass


def get_fernet_key(password: str) -> bytes:
    """Derive the original Fernet key for reading legacy archives."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def _cipher(password: str, salt: bytes) -> AESGCM:
    key = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(password.encode())
    return AESGCM(key)


def encrypt_backup(source: BinaryIO, output: BinaryIO, password: str) -> None:
    """Write v2 records with per-archive keys, ordered nonces and an authenticated end marker."""
    if not password or password == DEFAULT_BACKUP_PASSWORD:
        raise ValueError("Set a strong FORTRESS_BACKUP_PASSWORD")
    salt = os.urandom(SALT_BYTES)
    header = MAGIC + salt
    cipher = _cipher(password, salt)
    output.write(header)
    for index in count():
        data = source.read(CHUNK_BYTES)
        length = LENGTH.pack(len(data))
        nonce = index.to_bytes(12, "big")
        output.write(length)
        output.write(cipher.encrypt(nonce, data, header + length))
        if not data:
            return


def _read_exact(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise InvalidBackup("Incomplete backup archive")
    return data


def decrypt_backup(source: BinaryIO, output: BinaryIO | None, password: str) -> None:
    """Authenticate v1 or v2. Only publish or import output after this returns."""
    if source.read(len(MAGIC)) != MAGIC:
        source.seek(0)
        try:
            data = Fernet(get_fernet_key(password)).decrypt(source.read())
        except InvalidToken as exc:
            raise InvalidBackup("Invalid backup or wrong FORTRESS_BACKUP_PASSWORD") from exc
        if output is not None:
            output.write(data)
        return

    salt = _read_exact(source, SALT_BYTES)
    header = MAGIC + salt
    cipher = _cipher(password, salt)
    for index in count():
        length = _read_exact(source, LENGTH.size)
        size, = LENGTH.unpack(length)
        if size > CHUNK_BYTES:
            raise InvalidBackup("Invalid backup record length")
        encrypted = _read_exact(source, size + TAG_BYTES)
        try:
            data = cipher.decrypt(index.to_bytes(12, "big"), encrypted, header + length)
        except InvalidTag as exc:
            raise InvalidBackup("Invalid backup or wrong FORTRESS_BACKUP_PASSWORD") from exc
        if not data:
            if source.read(1):
                raise InvalidBackup("Unexpected data after the backup end marker")
            return
        if output is not None:
            output.write(data)


@contextmanager
def backup_output(destination: Path):
    """Publish an owner-only file once complete, preserving any existing output on failure."""
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".backup-", delete=False) as output:
        temporary = Path(output.name)
        try:
            yield output
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, destination)
            directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
