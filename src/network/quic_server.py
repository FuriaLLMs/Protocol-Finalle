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

from src.core.peer_manager import PeerManager
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
    Supports: HANDSHAKE and MESSAGE types.
    """
    def __init__(self, *args, 
                 identity_module: Optional[QuantumIdentity] = None,
                 encryption_module: Optional[QuantumEncryption] = None,
                 peer_manager: Optional[PeerManager] = None,
                 listening_port: int = 4433,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.identity_module = identity_module
        self.encryption_module = encryption_module
        self.peer_manager = peer_manager
        self.listening_port = listening_port
        self.buffer = b""

    def quic_event_received(self, event: QuicEvent):
        if isinstance(event, StreamDataReceived):
            self.buffer += event.data
            try:
                message_str = self.buffer.decode('utf-8')
                packet = json.loads(message_str)
                self._process_json_packet(packet)
                self.buffer = b"" 
            except json.JSONDecodeError:
                pass
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                self.buffer = b""

    def _process_json_packet(self, packet: Dict):
        """
        Processes a JSON tactical packet (HANDSHAKE or MESSAGE).
        
        Common Fields:
        - type: "HANDSHAKE" | "MESSAGE"
        - sender_id: Base64 Dilithium PubKey
        - signature: Base64 Signature of payload
        - payload: Dict (Content varies by type)
        """
        try:
            # 1. Extract Common Fields
            msg_type = packet.get("type", "MESSAGE") # Default to MESSAGE for backward compat if needed
            sender_pubkey_b64 = packet.get("sender_id")
            signature_b64 = packet.get("signature")
            payload = packet.get("payload", {})
            
            if not (sender_pubkey_b64 and signature_b64 and payload):
                raise ValueError("Incomplete packet structure.")

            sender_pubkey = base64.b64decode(sender_pubkey_b64)
            signature = base64.b64decode(signature_b64)

            # 2. Verify Signature
            # For HANDSHAKE: Payload is the raw JSON string of the payload dict? 
            # OR we reconstruct the bytes. The client must sign consistent bytes.
            # Decision: The client signs the concatenated values of key fields in payload.
            # To be robust, let's assume the client signs:
            # HANDSHAKE: node_id + dilithium_pk + kyber_pk + port (as string/bytes)
            # MESSAGE: kyber_capsule + aes_nonce + ciphertext
            
            body_to_verify = b""
            
            if msg_type == "HANDSHAKE":
                # Reconstruct bytes: node_id + dilithium_pk + kyber_pk
                # (Assuming strict ordering or specific format from client)
                # Let's simplify: Client signs the Dumped JSON of payload? No, canonical JSON is hard.
                # Client signs: node_id.encode() + dilithium_pk (bytes) + kyber_pk (bytes)
                
                # Extract fields
                node_id = payload.get("node_id", "")
                dilithium_pk_b64 = payload.get("dilithium_pk", "")
                kyber_pk_b64 = payload.get("kyber_pk", "")
                
                dilithium_pk = base64.b64decode(dilithium_pk_b64)
                kyber_pk = base64.b64decode(kyber_pk_b64)
                
                body_to_verify = node_id.encode('utf-8') + dilithium_pk + kyber_pk
                
            elif msg_type == "MESSAGE":
                kyber_capsule = base64.b64decode(payload.get("kyber_capsule", ""))
                aes_nonce = base64.b64decode(payload.get("aes_nonce", ""))
                ciphertext = base64.b64decode(payload.get("ciphertext", ""))
                body_to_verify = kyber_capsule + aes_nonce + ciphertext
            
            # Verify
            is_valid = QuantumIdentity.verify_signature(
                data=body_to_verify,
                signature=signature,
                public_key=sender_pubkey
            )
            
            if not is_valid:
                logger.warning(f"{Fore.RED}⚠️  INVALID SIGNATURE ({msg_type}) from {sender_pubkey_b64[:8]}... Dropping.{Style.RESET_ALL}")
                return

            # 3. Process by Type
            if msg_type == "HANDSHAKE":
                self._handle_handshake(sender_pubkey_b64, payload, dilithium_pk, kyber_pk)
            elif msg_type == "MESSAGE":
                self._handle_message(sender_pubkey_b64, payload)

        except Exception as e:
            logger.error(f"Packet processing failed: {e}")

    def _handle_handshake(self, sender_id: str, payload: Dict, d_pk: bytes, k_pk: bytes):
        node_id = payload.get("node_id")
        port = payload.get("listening_port")
        
        # Determine Sender IP from transport
        # connection.get_extra_info('peername') returns (ip, port)
        # We need the IP to reply back.
        peer_ip = "127.0.0.1" # Fallback
        try:
            if self._transport:
                peer_info = self._transport.get_extra_info('peername')
                if peer_info:
                    peer_ip = peer_info[0]
        except Exception:
            pass

        print(f"\n{Fore.CYAN}🤝 HANDSHAKE RECEIVED{Style.RESET_ALL}")
        print(f"Node ID: {node_id}")
        print(f"Kyber PK: {len(k_pk)} bytes")
        print(f"Peer IP: {peer_ip}:{port}")
        
        if self.peer_manager:
            try:
                # Check if peer is new
                existing_peer = self.peer_manager.get_peer(node_id)
                
                # Add/Update Peer
                self.peer_manager.add_peer(node_id, peer_ip, port, d_pk, k_pk)
                print(f"{Fore.GREEN}✅ ALLY REGISTERED: {node_id[:8]}...{Style.RESET_ALL}")
                
                # If peer was NEW, send OUR keys back (Auto-Handshake)
                if not existing_peer and self.identity_module and self.encryption_module:
                    print(f"{Fore.YELLOW}>> SENDING HANDSHAKE REPLY to {peer_ip}:{port}...{Style.RESET_ALL}")
                    
                    # Import here to avoid circular dependency
                    from src.network.p2p_client import send_handshake
                    
                    # Launch background task for reply
                    asyncio.create_task(send_handshake(
                        target_ip=peer_ip,
                        target_port=port,
                        my_identity=self.identity_module,
                        my_encryption=self.encryption_module,
                        listening_port=self.listening_port
                    ))
                    
            except Exception as e:
                logger.error(f"Failed to add/reply peer: {e}")
        
        print(f"CMD > ", end="", flush=True)

    def _handle_message(self, sender_id: str, payload: Dict):
        # ... Decryption Logic ...
        kyber_capsule = base64.b64decode(payload.get("kyber_capsule", ""))
        aes_nonce = base64.b64decode(payload.get("aes_nonce", ""))
        ciphertext = base64.b64decode(payload.get("ciphertext", ""))
        
        if not self.encryption_module:
            return

        try:
            decrypt_bundle = {
                'kyber_capsule': kyber_capsule,
                'aes_nonce': aes_nonce,
                'ciphertext': ciphertext
            }
            plaintext = self.encryption_module.decrypt_message(decrypt_bundle)
            
            print(f"\n{Fore.GREEN}⚡ TACTICAL MESSAGE RECEIVED ⚡{Style.RESET_ALL}")
            print(f"{Fore.CYAN}FROM:{Style.RESET_ALL} {sender_id[:16]}...")
            print(f"{Fore.GREEN}MSG :{Style.RESET_ALL} {plaintext}\n")
            print(f"CMD > ", end="", flush=True)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")


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
    encryption_module: Optional[QuantumEncryption] = None,
    peer_manager: Optional[PeerManager] = None
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
        encryption_module=encryption_module,
        peer_manager=peer_manager,
        listening_port=port
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
