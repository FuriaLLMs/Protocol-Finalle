import asyncio
import logging
import struct
from typing import Optional

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from src.core.identity import QuantumIdentity
from src.core.encryption import QuantumEncryption
from src.network.quic_server import generate_ephemeral_cert

# Configure logging
logger = logging.getLogger(__name__)

import json
import base64

# ... (Imports remain, adding json/base64 via context if not present, but better to ensure)

async def send_tactical_message(
    target_ip: str,
    target_port: int,
    message: str,
    my_identity: QuantumIdentity,
    target_kyber_public_key: bytes,
    encryption_module: QuantumEncryption
):
    """
    Encodes, Encrypts, Signs, and Sends a message (JSON Format).
    """
    logger.info(f"Preparing to send message to {target_ip}:{target_port}...")

    # 1. ENCRYPTION (Centralized)
    logger.debug("Encrypting message...")
    encrypted_data = encryption_module.encrypt_message(target_kyber_public_key, message)
    
    capsule = encrypted_data['kyber_capsule']
    nonce = encrypted_data['aes_nonce']
    ciphertext = encrypted_data['ciphertext']
    
    # 2. SIGNING
    # Sign the raw bytes (Capsule + Nonce + Ciphertext)
    body_to_sign = capsule + nonce + ciphertext
    signature = my_identity.sign_data(body_to_sign)
    
    # 3. PACKET ASSEMBLY (JSON)
    packet_dict = {
        "sender_id": base64.b64encode(my_identity.public_key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "payload": {
            "kyber_capsule": base64.b64encode(capsule).decode('utf-8'),
            "aes_nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
        }
    }
    
    packet_bytes = json.dumps(packet_dict).encode('utf-8')
    
    # 4. SEND VIA QUIC
    logger.info(f"Sending packet ({len(packet_bytes)} bytes)...")
    
    configuration = generate_ephemeral_cert()
    configuration.is_client = True
    
    # Disable TLS certificate verification
    import ssl
    configuration.verify_mode = ssl.CERT_NONE
    
    try:
        async with connect(
            target_ip,
            target_port,
            configuration=configuration,
        ) as protocol:
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol._quic.send_stream_data(stream_id, packet_bytes, end_stream=True)
            logger.info("Message sent successfully.")
            await asyncio.sleep(0.5)
            protocol.close()
            await protocol.wait_closed()
            
    except Exception as e:
        logger.error(f"Failed to send message: {e}")
        raise e
