"""Business-logic services for VulnaDash."""

from app.services.audit import record_audit
from app.services.bootstrap import (
    ensure_bootstrap_admin,
    ensure_default_organization,
    run_bootstrap,
)
from app.services.ca import (
    CertificateAuthority,
    CertificateAuthorityError,
    certificate_fingerprint,
    get_ca,
)
from app.services.enrollment import GeneratedToken, generate_token, hash_token
from app.services.jobs import JobValidationError, build_job_envelope, create_scan_job
from app.services.policy import build_policy_document
from app.services.scopes import (
    ScopeValidationError,
    find_overlaps,
    normalize_cidr,
    validate_cidr,
)
from app.services.signing import (
    Ed25519Signer,
    SigningError,
    canonical_bytes,
    document_hash,
    get_signer,
)

__all__ = [
    "CertificateAuthority",
    "CertificateAuthorityError",
    "Ed25519Signer",
    "GeneratedToken",
    "JobValidationError",
    "ScopeValidationError",
    "SigningError",
    "build_job_envelope",
    "build_policy_document",
    "create_scan_job",
    "canonical_bytes",
    "certificate_fingerprint",
    "document_hash",
    "ensure_bootstrap_admin",
    "ensure_default_organization",
    "find_overlaps",
    "generate_token",
    "get_ca",
    "get_signer",
    "hash_token",
    "normalize_cidr",
    "record_audit",
    "run_bootstrap",
    "validate_cidr",
]
