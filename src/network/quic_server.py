import asyncio
import logging
from typing import Optional, cast
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

# Configure logging
logger = logging.getLogger(__name__)

class TacticalProtocol(QuicConnectionProtocol):
    """
    Protocol handler for the Tactical P2P Network.
    Handles encrypted streams over UDP/QUIC.
    """
    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            data = event.data
            stream_id = event.stream_id
            
            # For now, just log received data.
            # In production, this would pass data to a handler or identity verifier.
            logger.info(f"[Stream {stream_id}] Received {len(data)} bytes: {data!r}")
            
            # Echo back for testing purposes (optional, good for verification)
            # self._quic.send_stream_data(stream_id, data, end_stream=event.end_stream)

def generate_ephemeral_cert() -> QuicConfiguration:
    """
    Generates a self-signed certificate and private key in MEMORY ONLY.
    
    Returns:
        QuicConfiguration: A configuration object with the ephemeral cert/key loaded.
    """
    logger.info("Generating ephemeral TLS certificate (RAM Only)...")
    
    # 1. Generate Private Key (Elliptic Curve - SECP256R1)
    private_key = ec.generate_private_key(ec.SECP256R1())
    
    # 2. Generate Self-Signed Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Tactical Node"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Resistance P2P"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # 3. Create QuicConfiguration
    # Note: alpn_protocols is required for QUIC
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["tactical-v1"]
    )

    # 4. Inject Keys directly into configuration (Bypassing disk I/O)
    # aioquic supports passing cryptography objects directly
    configuration.certificate = cert
    configuration.private_key = private_key
    
    logger.info("Ephemeral certificate generated and loaded.")
    return configuration

async def start_node(host: str, port: int):
    """
    Starts the QUIC server node.
    """
    configuration = generate_ephemeral_cert()
    
    logger.info(f"Starting QUIC Server on {host}:{port} (UDP)")
    
    # serve creates the datagram endpoint
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=TacticalProtocol,
    )
    
    # Keep running
    await asyncio.Future()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        # Run server on localhost:4433
        asyncio.run(start_node("127.0.0.1", 4433))
    except KeyboardInterrupt:
        logger.info("Server stopped.")
