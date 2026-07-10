"""Unit tests for the internal certificate authority."""

from __future__ import annotations

from pathlib import Path

import pytest
from app.services.ca import (
    CertificateAuthority,
    CertificateAuthorityError,
    certificate_fingerprint,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _make_csr(common_name: str = "probe") -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def test_create_and_reload_ca(tmp_path: Path) -> None:
    key_path = tmp_path / "ca_key.pem"
    cert_path = tmp_path / "ca_cert.pem"
    ca = CertificateAuthority.load_or_create(key_path, cert_path)
    assert key_path.exists() and cert_path.exists()
    # Private key file is owner-only.
    assert (key_path.stat().st_mode & 0o777) == 0o600
    # Reloading yields the same CA certificate.
    ca2 = CertificateAuthority.load_or_create(key_path, cert_path)
    assert ca.cert_pem == ca2.cert_pem


def test_sign_csr_sets_server_chosen_identity(tmp_path: Path) -> None:
    ca = CertificateAuthority.load_or_create(tmp_path / "k.pem", tmp_path / "c.pem")
    cert = ca.sign_csr(_make_csr("attacker-chosen"), common_name="assigned-id", validity_days=90)
    # The server's chosen CN wins, not the CSR's.
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "assigned-id"
    # It is a client-auth, non-CA certificate.
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    # Signed by the CA.
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem)
    assert cert.issuer == ca_cert.subject


def test_sign_rejects_garbage_csr(tmp_path: Path) -> None:
    ca = CertificateAuthority.load_or_create(tmp_path / "k.pem", tmp_path / "c.pem")
    with pytest.raises(CertificateAuthorityError):
        ca.sign_csr(b"not a csr", common_name="x", validity_days=90)


def test_fingerprint_is_stable_sha256(tmp_path: Path) -> None:
    ca = CertificateAuthority.load_or_create(tmp_path / "k.pem", tmp_path / "c.pem")
    cert = ca.sign_csr(_make_csr(), common_name="id", validity_days=90)
    fp = certificate_fingerprint(cert)
    assert len(fp) == 64 and fp == fp.lower()
    assert certificate_fingerprint(cert) == fp
