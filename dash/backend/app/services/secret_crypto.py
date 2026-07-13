"""Purpose-separated encryption for reusable application secrets."""

from __future__ import annotations

import base64
from enum import StrEnum

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecretPurpose(StrEnum):
    TOTP_SEED = "totp_seed"
    OIDC_CLIENT_SECRET = "oidc_client_secret"  # noqa: S105 - purpose label
    OIDC_FLOW_SECRET = "oidc_flow_secret"  # noqa: S105 - purpose label
    SAML_IDP_CERTIFICATE = "saml_idp_certificate"
    SAML_SP_CERTIFICATE = "saml_sp_certificate"
    SAML_SP_PRIVATE_KEY = "saml_sp_private_key"
    CREDENTIAL_SSH_SECRET = "credential_ssh_secret"  # noqa: S105 - purpose label
    CREDENTIAL_WINRM_SECRET = "credential_winrm_secret"  # noqa: S105 - purpose label
    TICKET_CONNECTOR_SECRET = "ticket_connector_secret"  # noqa: S105 - purpose label
    INVENTORY_CONNECTOR_SECRET = "inventory_connector_secret"  # noqa: S105
    INVENTORY_CSV_SOURCE = "inventory_csv_source"  # noqa: S105
    REPORT_EXPORT_PASSWORD = "report_export_password"  # noqa: S105


_CONTEXT = {
    SecretPurpose.TOTP_SEED: b"vulna-totp-seed-encryption-v1",
    SecretPurpose.OIDC_CLIENT_SECRET: b"vulna-oidc-client-secret-encryption-v1",
    SecretPurpose.OIDC_FLOW_SECRET: b"vulna-oidc-flow-secret-encryption-v1",
    SecretPurpose.SAML_IDP_CERTIFICATE: b"vulna-saml-idp-certificate-encryption-v1",
    SecretPurpose.SAML_SP_CERTIFICATE: b"vulna-saml-sp-certificate-encryption-v1",
    SecretPurpose.SAML_SP_PRIVATE_KEY: b"vulna-saml-sp-private-key-encryption-v1",
    SecretPurpose.CREDENTIAL_SSH_SECRET: b"vulna-credential-ssh-secret-encryption-v1",
    SecretPurpose.CREDENTIAL_WINRM_SECRET: b"vulna-credential-winrm-secret-encryption-v1",
    SecretPurpose.TICKET_CONNECTOR_SECRET: b"vulna-ticket-connector-secret-encryption-v1",
    SecretPurpose.INVENTORY_CONNECTOR_SECRET: b"vulna-inventory-connector-secret-encryption-v1",
    SecretPurpose.INVENTORY_CSV_SOURCE: b"vulna-inventory-csv-source-encryption-v1",
    SecretPurpose.REPORT_EXPORT_PASSWORD: b"vulna-report-export-password-encryption-v1",
}


class SecretDecryptionError(ValueError):
    """Raised when purpose-bound ciphertext cannot be authenticated."""


def _fernet(master_secret: str, purpose: SecretPurpose) -> Fernet:
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_CONTEXT[purpose],
    ).derive(master_secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(master_secret: str, purpose: SecretPurpose, plaintext: str) -> str:
    return _fernet(master_secret, purpose).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(master_secret: str, purpose: SecretPurpose, ciphertext: str) -> str:
    try:
        return _fernet(master_secret, purpose).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise SecretDecryptionError("Secret ciphertext is invalid for this purpose") from exc
