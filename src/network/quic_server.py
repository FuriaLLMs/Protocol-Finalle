import asyncio
import logging
import json
import base64
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
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Configure logging
logger = logging.getLogger(__name__)

class TacticalProtocol(QuicConnectionProtocol):
    """
    Protocol handler for the Tactical P2P Network (JSON/Base64).
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
            
            # Attempt to process buffer (Expect JSON)
            try:
                # We assume one message per stream for simplicity in this tactical protocol
                # If we were doing continuous streams, we'd need length prefixing or delimiters
                message_str = self.buffer.decode('utf-8')
                packet = json.loads(message_str)
                self._process_json_packet(packet)
                self.buffer = b"" # Reset buffer after success
            except json.JSONDecodeError:
                # Incomplete data or invalid JSON, wait for more
                pass
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                self.buffer = b""

    def _process_json_packet(self, packet: Dict):
        """
        Processes a JSON tactical packet.
        Expected Format:
        {
          "sender_id": "Base64_PublicKey",
          "signature": "Base64_Sig",
          "payload": {
             "kyber_capsule": "Base64...",
             "aes_nonce": "Base64...",
             "ciphertext": "Base64..."
          }
        }
        """
        try:
            # 1. Extract and Decode Fields
            sender_pubkey_b64 = packet.get("sender_id")
            signature_b64 = packet.get("signature")
            payload = packet.get("payload", {})
            
            if not (sender_pubkey_b64 and signature_b64 and payload):
                raise ValueError("Incomplete packet structure.")

            sender_pubkey = base64.b64decode(sender_pubkey_b64)
            signature = base64.b64decode(signature_b64)
            
            kyber_capsule = base64.b64decode(payload.get("kyber_capsule", ""))
            aes_nonce = base64.b64decode(payload.get("aes_nonce", ""))
            ciphertext = base64.b64decode(payload.get("ciphertext", ""))
            
            if not (kyber_capsule and aes_nonce and ciphertext):
                raise ValueError("Incomplete payload.")

            # 2. Verify Signature (Dilithium)
            # Reconstruct the body that was signed: Capsule + Nonce + Ciphertext
            # This ensures the crypto materials verify against the signature
            body_to_verify = kyber_capsule + aes_nonce + ciphertext
            
            is_valid = QuantumIdentity.verify_signature(
                data=body_to_verify,
                signature=signature,
                public_key=sender_pubkey
            )
            
            if not is_valid:
                logger.warning(f"{Fore.RED}⚠️  INVALID SIGNATURE from {sender_pubkey_b64[:8]}... Dropping.{Style.RESET_ALL}")
                return

            # 3. Decrypt (Kyber + AES)
            if not self.encryption_module:
                logger.error("Encryption module not initialized.")
                return
                
            decrypt_bundle = {
                'kyber_capsule': kyber_capsule,
                'aes_nonce': aes_nonce,
                'ciphertext': ciphertext
            }
            
            plaintext = self.encryption_module.decrypt_message(decrypt_bundle)
            
            # 4. Success Output
            print(f"\n{Fore.GREEN}⚡ TACTICAL MESSAGE RECEIVED ⚡{Style.RESET_ALL}")
            print(f"{Fore.CYAN}FROM:{Style.RESET_ALL} {sender_pubkey_b64[:16]}...")
            print(f"{Fore.GREEN}MSG :{Style.RESET_ALL} {plaintext}\n")
            print(f"CMD > ", end="", flush=True) # Restore prompt
            
        except Exception as e:
            logger.error(f"Packet processing failed: {e}")

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

async def start_node(
    host: str, 
    port: int,
    identity_module: Optional[QuantumIdentity] = None,
    encryption_module: Optional[QuantumEncryption] = None
):
    """
    Starts the QUIC server node.
    """
    if encryption_module:
        pub_key_b64 = encryption_module.export_public_key()
        print(f"\n{Fore.YELLOW}=== SERVER STARTED ==={Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}KYBER PUBLIC KEY:{Style.RESET_ALL} {pub_key_b64}")
        print(f"{Fore.YELLOW}Listening on {host}:{port} (UDP/QUIC)...{Style.RESET_ALL}\n")

    configuration = generate_ephemeral_cert()
    
    protocol_factory = functools.partial(
        TacticalProtocol, 
        identity_module=identity_module,
        encryption_module=encryption_module
    )

    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=protocol_factory,
    )
    
    await asyncio.Future()

if __name__ == "__main__":
    # Test Entry point
    asyncio.run(start_node("127.0.0.1", 4433))
