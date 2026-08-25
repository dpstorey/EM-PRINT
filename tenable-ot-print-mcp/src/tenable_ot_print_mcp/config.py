"""Encrypted configuration persisted to /data/config.enc.

Adapted from EM-MCP's config.py — same Fernet-encrypted-file pattern,
same single-bearer-token model. Adds `output_dir`: where rendered
reports get written (the bind-mounted filestore — see design-notes.md
§4.3; this server never needs to know what's actually backing that
mount point).
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

CONFIG_FILENAME = "config.enc"
KEY_FILENAME = "config.key"


@dataclass
class Config:
    tenable_url: str
    tenable_api_key: str
    tls_verify: bool
    bearer_token: str
    icp_machine_id: str | None = None
    setup_completed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Config:
        return cls(**d)


class ConfigStore:
    """Reads and writes the encrypted config file under data_dir."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config_path = data_dir / CONFIG_FILENAME
        self.key_path = data_dir / KEY_FILENAME

    def _load_or_create_key(self) -> bytes:
        if self.key_path.is_file():
            return self.key_path.read_bytes()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        os.chmod(self.key_path, 0o600)
        return key

    def is_configured(self) -> bool:
        return self.config_path.is_file()

    def load(self) -> Config:
        if not self.is_configured():
            raise FileNotFoundError(f"No config at {self.config_path}")
        key = self._load_or_create_key()
        try:
            payload = Fernet(key).decrypt(self.config_path.read_bytes())
        except InvalidToken as e:
            raise RuntimeError(
                f"Config decryption failed — the key under {self.key_path} does not "
                f"match {self.config_path}. Delete both and re-run setup."
            ) from e
        return Config.from_dict(json.loads(payload.decode("utf-8")))

    def save(self, cfg: Config) -> None:
        key = self._load_or_create_key()
        payload = json.dumps(cfg.to_dict()).encode("utf-8")
        self.config_path.write_bytes(Fernet(key).encrypt(payload))
        os.chmod(self.config_path, 0o600)


def generate_bearer_token() -> str:
    return secrets.token_urlsafe(32)


def get_output_dir() -> Path:
    """The bind-mounted filestore reports get written to.

    Protocol-agnostic by design (see design-notes.md §4.3): this server
    only ever writes inside this path via plain filesystem calls. What
    actually backs it (SMB/NFS/local disk) is the host's concern.
    """
    p = Path(os.environ.get("MCP_OUTPUT_DIR", "./output"))
    p.mkdir(parents=True, exist_ok=True)
    return p
