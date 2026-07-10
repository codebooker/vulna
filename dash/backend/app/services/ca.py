"""Internal certificate authority for VulnaScout client certificates.

The orchestrator runs a small private CA. During enrollment a probe generates
its own key pair locally and sends a certificate-signing request; the CA signs
it into a short-lived client certificate used for mutual TLS. The probe's
private key never leaves the probe.

The CA uses ECDSA P-256, which is widely supported for mTLS client
authentication. The CA private key is written with ``0600`` permissions and must
be kept secret and backed up — losing it means re-enrolling every probe.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.core.config import Settings, get_settings

_CA_COMMON_NAME = "Vulna Internal CA"
_CA_VALIDITY_DAYS = 3650  # 10 years


class CertificateAuthorityError(RuntimeError):
    """Raised when CA material cannot be loaded or a CSR cannot be signed."""


def certificate_fingerprint(cert: x509.Certificate) -> str:
    """Return the lowercase hex SHA-256 fingerprint of a certificate (DER)."""
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


class CertificateAuthority:
    """A private CA that signs VulnaScout client certificates."""

    def __init__(self, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
        self._key = key
        self._cert = cert

    # -- construction ---------------------------------------------------------

    @classmethod
    def load_or_create(cls, key_path: Path, cert_path: Path) -> CertificateAuthority:
        """Load the CA from disk, generating and persisting it if absent."""
        if key_path.exists() and cert_path.exists():
            return cls.load(key_path, cert_path)
        return cls.create_and_save(key_path, cert_path)

    @classmethod
    def load(cls, key_path: Path, cert_path: Path) -> CertificateAuthority:
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except (ValueError, OSError) as exc:
            raise CertificateAuthorityError(f"Could not load CA material: {exc}") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CertificateAuthorityError("CA key is not an EC private key")
        return cls(key, cert)

    @classmethod
    def create_and_save(cls, key_path: Path, cert_path: Path) -> CertificateAuthority:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_COMMON_NAME)])
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=_CA_VALIDITY_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        _write_secret(key_path, key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        _write_public(cert_path, cert.public_bytes(serialization.Encoding.PEM))
        return cls(key, cert)

    # -- operations -----------------------------------------------------------

    @property
    def cert_pem(self) -> bytes:
        """The CA certificate in PEM form (safe to distribute to probes)."""
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def sign_csr(
        self,
        csr_pem: bytes,
        *,
        common_name: str,
        validity_days: int,
    ) -> x509.Certificate:
        """Sign a probe CSR into a bounded-validity client certificate.

        The subject common name is set by the server (the probe id), never taken
        from the CSR, so a probe cannot choose its own identity.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise CertificateAuthorityError(f"Invalid CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise CertificateAuthorityError("CSR signature is invalid")

        now = dt.datetime.now(dt.UTC)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


def _write_public(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o644)


_ca_instance: CertificateAuthority | None = None


def get_ca(settings: Settings | None = None) -> CertificateAuthority:
    """Return the process-wide CA, loading or creating it from settings paths."""
    global _ca_instance
    if _ca_instance is None:
        settings = settings or get_settings()
        _ca_instance = CertificateAuthority.load_or_create(
            Path(settings.ca_key_path), Path(settings.ca_cert_path)
        )
    return _ca_instance


def reset_ca_cache() -> None:
    """Reset the cached CA (used by tests that point at a fresh CA directory)."""
    global _ca_instance
    _ca_instance = None
