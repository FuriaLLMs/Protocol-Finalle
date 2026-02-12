import asyncio
import logging
import struct
import functools
from typing import Optional, cast, Callable, Dict
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived

from src.core.identity import QuantumIdentity
from src.core.encryption import QuantumEncryption

# Configure logging
logger = logging.getLogger(__name__)

class TacticalProtocol(QuicConnectionProtocol):
    """
    Protocol handler for the Tactical P2P Network.
    Handles encrypted streams over UDP/QUIC.
    """
    def __init__(self, *args, 
                 identity_module: Optional[QuantumIdentity] = None,
                 encryption_module: Optional[QuantumEncryption] = None,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.identity_module = identity_module
        self.encryption_module = encryption_module
        self.buffer = b""

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            self.buffer += event.data
            
            # Attempt to process buffer if we have enough data
            try:
                self._process_packet()
            except Exception as e:
                # If error is just "not enough data", we wait for more.
                # If it's a parsing error, we log it.
                if "Not enough data" not in str(e):
                    logger.error(f"Error processing packet: {e}")
                    self.buffer = b"" # Clear bad buffer

    def _process_packet(self):
        """
        Parses and decrypts the P2P packet.
        Format:
        [SENDER_PUBKEY_LEN (4B)] + [SENDER_PUBKEY] + 
        [SIGNATURE_LEN (4B)]     + [SIGNATURE] + 
        [CIPHERTEXT_LEN (4B)]    + [CIPHERTEXT] + 
        [PAYLOAD (Encrypted msg)]
        """
        data = self.buffer
        offset = 0

        # Helper to read N bytes
        def read(n):
            nonlocal offset
            if offset + n > len(data):
                raise ValueError("Not enough data")
            res = data[offset : offset + n]
            offset += n
            return res

        # 1. Parse Sender PubKey
        pubkey_len = struct.unpack("!I", read(4))[0]
        sender_pubkey = read(pubkey_len)

        # 2. Parse Signature
        sig_len = struct.unpack("!I", read(4))[0]
        signature = read(sig_len)

        # 3. Parse Ciphertext
        ct_len = struct.unpack("!I", read(4))[0]
        ciphertext = read(ct_len)

        # 4. Get Payload (Rest of buffer for now, assuming one packet per stream)
        # Note: In a continuous stream, we'd need a payload length field.
        # For this PoC using quick streams, we take the rest.
        encrypted_payload = data[offset:]
        if len(encrypted_payload) == 0:
             raise ValueError("Not enough data (No payload)")

        # --- VERIFICATION & DECRYPTION ---

        # A. Verify Signature (Dilithium)
        # Signature covers: Ciphertext + EncryptedPayload
        body_to_verify = ciphertext + encrypted_payload
        
        # We need a way to verify using the bytes we received.
        # QuantumIdentity.verify_signature is static.
        is_valid = QuantumIdentity.verify_signature(body_to_verify, signature, sender_pubkey)
        
        if not is_valid:
            logger.warning("Packet signature verification FAILED. Dropping.")
            return

        logger.info(f"Signature Verified (Sender: {sender_pubkey[:8].hex()}...)")

        # B. Decapsulate (Kyber)
        if not self.encryption_module:
            logger.error("No encryption module available to decrypt.")
            return

        try:
            shared_secret = self.encryption_module.decapsulate(ciphertext)
            logger.debug("Decapsulation successful. Shared secret derived.")
        except Exception as e:
            logger.error(f"Decapsulation failed: {e}")
            return

        # C. Decrypt Payload (AES-GCM)
        try:
            plaintext = QuantumEncryption.decrypt_message(encrypted_payload, shared_secret)
            logger.info(f"MESSAGE RECEIVED: {plaintext}")
            # Reset buffer only after successful processing
            self.buffer = b"" 
        except Exception as e:
            logger.error(f"Decryption failed: {e}")

def generate_ephemeral_cert() -> QuicConfiguration:
    """
    Generates a self-signed certificate and private key in MEMORY ONLY.
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
    configuration.certificate = cert
    configuration.private_key = private_key
    
    logger.info("Ephemeral certificate generated and loaded.")
    return configuration

async def start_node(
    host: str, 
    port: int,
    identity_module: Optional[QuantumIdentity] = None,
    encryption_module: Optional[QuantumEncryption] = None
):
    """
    Starts the QUIC server node.
    """
    configuration = generate_ephemeral_cert()
    
    logger.info(f"Starting QUIC Server on {host}:{port} (UDP)")
    
    # Create a partial to inject our modules into the protocol constructor
    protocol_factory = functools.partial(
        TacticalProtocol, 
        identity_module=identity_module,
        encryption_module=encryption_module
    )

    # serve creates the datagram endpoint
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=protocol_factory,
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
