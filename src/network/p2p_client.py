import asyncio
import logging
import struct
from typing import Optional

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

from src.core.identity import QuantumIdentity
from src.core.encryption import QuantumEncryption
from src.security.utils import generate_ephemeral_cert

# Configure logging
logger = logging.getLogger(__name__)

import json
import base64
import hashlib

import time

async def send_handshake(
    target_ip: str,
    target_port: int,
    my_identity: QuantumIdentity,
    my_encryption: QuantumEncryption,
    listening_port: int = 4433
):
    """
    Sends a HANDSHAKE packet to a target node to share public keys.
    Includes Timestamp for Replay Protection.
    """
    logger.info(f"Sending HANDSHAKE to {target_ip}:{target_port}...")
    
    # 1. Prepare Payload
    # Generate a simple Node ID (Hash of PubKey)
    node_id = hashlib.sha256(my_identity.public_key).hexdigest()
    
    dilithium_pk_b64 = my_identity.export_public_key()
    kyber_pk_b64 = my_encryption.export_public_key()
    
    # Replay Protection
    timestamp = int(time.time())
    
    payload = {
        "node_id": node_id,
        "dilithium_pk": dilithium_pk_b64,
        "kyber_pk": kyber_pk_b64,
        "listening_port": listening_port,
        "timestamp": timestamp
    }
    
    # 2. Sign Payload (Consistent with Server Verification)
    # Body: node_id + dilithium_pk (bytes) + kyber_pk (bytes) + timestamp (str->bytes)
    body_to_sign = (
        node_id.encode('utf-8') + 
        my_identity.public_key + 
        my_encryption.public_key +
        str(timestamp).encode('utf-8')
    )
    
    signature = my_identity.sign_data(body_to_sign)
    
    # 3. Construct Packet
    packet_dict = {
        "type": "HANDSHAKE",
        "sender_id": dilithium_pk_b64,
        "signature": base64.b64encode(signature).decode('utf-8'),
        "payload": payload
    }
    
    packet_bytes = json.dumps(packet_dict).encode('utf-8')
    
    # 4. Send
    await _send_raw_packet(target_ip, target_port, packet_bytes)

async def _send_raw_packet(target_ip, target_port, data):
    """Helper to send raw bytes via QUIC."""
    configuration = generate_ephemeral_cert()
    configuration.is_client = True
    
    import ssl
    configuration.verify_mode = ssl.CERT_NONE
    
    try:
        async with connect(
            target_ip,
            target_port,
            configuration=configuration,
        ) as protocol:
            stream_id = protocol._quic.get_next_available_stream_id()
            protocol._quic.send_stream_data(stream_id, data, end_stream=True)
            logger.info("Packet sent successfully.")
            await asyncio.sleep(0.5)
            protocol.close()
            await protocol.wait_closed()
    except Exception as e:
        logger.error(f"Failed to send packet: {e}")
        raise e

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
    Includes Timestamp for Replay Protection.
    """
    logger.info(f"Preparing to send message to {target_ip}:{target_port}...")

    # 1. ENCRYPTION (Centralized)
    logger.debug("Encrypting message...")
    encrypted_data = encryption_module.encrypt_message(target_kyber_public_key, message)
    
    capsule = encrypted_data['kyber_capsule']
    nonce = encrypted_data['aes_nonce']
    ciphertext = encrypted_data['ciphertext']
    
    # Replay Protection
    timestamp = int(time.time())

    # 2. SIGNING
    # Sign the raw bytes (Capsule + Nonce + Ciphertext + Timestamp)
    body_to_sign = (
        capsule + 
        nonce + 
        ciphertext + 
        str(timestamp).encode('utf-8')
    )
    
    signature = my_identity.sign_data(body_to_sign)
    
    # 3. PACKET ASSEMBLY (JSON)
    packet_dict = {
        "type": "MESSAGE",
        "sender_id": base64.b64encode(my_identity.public_key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "payload": {
            "kyber_capsule": base64.b64encode(capsule).decode('utf-8'),
            "aes_nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "timestamp": timestamp
        }
    }
    
    packet_bytes = json.dumps(packet_dict).encode('utf-8')
    
    # 4. SEND
    await _send_raw_packet(target_ip, target_port, packet_bytes)
