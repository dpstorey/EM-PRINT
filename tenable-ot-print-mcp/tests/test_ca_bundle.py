# SPDX-License-Identifier: Apache-2.0
"""Regression tests for custom-CA-bundle support (added after Dom's real EM
turned out to use an internally-signed TLS cert)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from tenable_ot_print_mcp.config import get_ca_bundle_path
from tenable_ot_print_mcp.tenable_client import TenableClient


def test_get_ca_bundle_path_none_when_absent():
    with tempfile.TemporaryDirectory() as tmp:
        assert get_ca_bundle_path(Path(tmp)) is None


def test_get_ca_bundle_path_default_location():
    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp)
        ca_file = data_dir / "tenable-ca.pem"
        ca_file.write_text("fake-pem-content")
        assert get_ca_bundle_path(data_dir) == ca_file


def test_get_ca_bundle_path_env_override(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        other = Path(tmp) / "custom.pem"
        other.write_text("x")
        monkeypatch.setenv("MCP_TENABLE_CA_BUNDLE", str(other))
        assert get_ca_bundle_path(Path(tmp)) == other


def test_get_ca_bundle_path_env_missing_file_raises(monkeypatch):
    monkeypatch.setenv("MCP_TENABLE_CA_BUNDLE", "/no/such/file.pem")
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(FileNotFoundError):
            get_ca_bundle_path(Path(tmp))


def test_tenable_client_verify_prefers_ca_bundle_over_tls_verify_flag():
    client = TenableClient(
        "https://em.example.com", "key", tls_verify=True, ca_bundle="/data/tenable-ca.pem"
    )
    assert client._verify == "/data/tenable-ca.pem"


def test_tenable_client_verify_falls_back_to_tls_verify_flag():
    client = TenableClient("https://em.example.com", "key", tls_verify=True)
    assert client._verify is True
