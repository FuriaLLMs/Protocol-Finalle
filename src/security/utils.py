import logging
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from aioquic.quic.configuration import QuicConfiguration

# Configure logging
logger = logging.getLogger(__name__)

def generate_ephemeral_cert() -> QuicConfiguration:
    """
    Generates a self-signed certificate and private key in MEMORY ONLY.
    """
    logger.info("Generating ephemeral TLS certificate (RAM Only)...")
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Tactical Node"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["tactical-v1"])
    configuration.certificate = cert
    configuration.private_key = private_key
    configuration.verify_mode = 0 # ssl.CERT_NONE
    return configuration
