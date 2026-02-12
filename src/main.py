import asyncio
import sys
import hashlib
import logging
from typing import NoReturn

import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

# Import local modules
# We use try-except to handle potential import errors gracefully during development
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from src.security import ram_guard
    from src.core.identity import QuantumIdentity
    from src.network import quic_server
except ImportError as e:
    print(f"{Fore.RED}[CRITICAL] Module import failed: {e}")
    sys.exit(1)

# Configure Logging (suppress low level logs for clean UI)
logging.basicConfig(level=logging.CRITICAL) 
# Create a specific logger for our app info if needed, or just use print for CLI UI.
# We will redirect quic_server logs to file or suppress them to keep UI clean?
# For now, let's keep them suppressed unless critical.

async def async_input(prompt: str) -> str:
    """
    Reads input asynchronously to avoid blocking the event loop.
    """
    return await asyncio.get_running_loop().run_in_executor(None, input, prompt)

async def main_loop(identity: QuantumIdentity):
    """
    Main application loop.
    """
    print(f"\n{Fore.CYAN}--- TACTICAL P2P TERMINAL ACTIVE ---{Style.RESET_ALL}")
    print(f"{Fore.WHITE}Type message to send (simulated) or '/exit' to quit.\n")

    while True:
        try:
            # Show prompt
            user_input = await async_input(f"{Fore.GREEN}CMD > {Fore.WHITE}")
            
            # Handle commands
            if user_input.strip().lower() in ["/exit", "/quit"]:
                raise KeyboardInterrupt
            
            if user_input.strip() == "":
                continue

            # Simulate sending (In future: quic_server.broadcast(user_input))
            # Just verify we can sign what we type
            signature = identity.sign_data(user_input.encode())
            sig_hex = signature.hex()[:16] # Show partial sig
            
            print(f"{Fore.BLUE}[SENT] {Fore.WHITE}{user_input}")
            print(f"{Fore.BLACK}{Style.BRIGHT}[SIG: {sig_hex}...]{Style.RESET_ALL}")
            
        except EOFError:
            break

async def start_application():
    """
    Boot sequence and main execution.
    """
    identity = None
    
    print(f"{Fore.WHITE}{Style.BRIGHT}INITIALIZING QUANTUM RESISTANCE NODE...{Style.RESET_ALL}")
    
    # --- STEP 1: RAM GUARD ---
    print(f"{Fore.WHITE}Engaging RAM Guard... ", end="")
    if ram_guard.lock_memory(strict=False):
        print(f"{Fore.GREEN}[LOCKED]")
    else:
        print(f"{Fore.YELLOW}[WARNING: SWAP RISK]")
        print(f"{Fore.YELLOW}   Could not lock memory. Run as root or adjust ulimit for full security.")

    # --- STEP 2: IDENTITY GENERATION ---
    print(f"{Fore.WHITE}Generating Quantum Identity (Dilithium-2)... ", end="")
    try:
        identity = QuantumIdentity()
        
        # Calculate a Node ID for display
        pub_key_bytes = identity.public_key
        node_id = hashlib.sha256(pub_key_bytes).hexdigest()[:12].upper()
        
        print(f"{Fore.GREEN}[OK]")
        print(f"{Fore.WHITE}NODE ID: {Fore.MAGENTA}{node_id}")
        
    except Exception as e:
        print(f"{Fore.RED}[FAILED]")
        print(f"{Fore.RED}Critical Error: {e}")
        return

    # --- STEP 3: NETWORK STARTUP ---
    HOST = "0.0.0.0" # Listen on all interfaces
    PORT = 4433
    
    print(f"{Fore.WHITE}Starting QUIC Tactic Server on port {PORT}... ", end="")
    
    # Start server as a background task
    server_task = asyncio.create_task(quic_server.start_node(HOST, PORT))
    print(f"{Fore.GREEN}[LISTENING]")

    # --- ENTER MAIN LOOP ---
    try:
        await main_loop(identity)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutdown sequence initiated...")
    finally:
        # --- CLEANUP ---
        if identity:
            print(f"{Fore.WHITE}Wiping cryptographic keys... ", end="")
            identity.wipe_memory()
            print(f"{Fore.GREEN}[WIPED]")
        
        print(f"{Fore.WHITE}Cleaning memory pages... ", end="")
        ram_guard.panic_clean()
        print(f"{Fore.GREEN}[CLEAN]")
        
        print(f"{Fore.RED}{Style.BRIGHT}SYSTEM HALTED.")
        
        # Cancel server task
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    try:
        asyncio.run(start_application())
    except KeyboardInterrupt:
        pass # Already handled in start_application, but just in case
