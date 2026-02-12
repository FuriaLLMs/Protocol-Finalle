import ctypes
import os
import sys
import gc
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Constants for mlockall
MCL_CURRENT = 1
MCL_FUTURE = 2

def lock_memory(strict: bool = False) -> bool:
    """
    Prevent the operating system from swapping this process's memory to disk.
    
    Uses the `mlockall` syscall via libc to lock all current and future
    memory pages into RAM. This is crucial for protecting sensitive data
    like cryptographic keys from being written to swap space.
    
    Args:
        strict (bool): If True, raises an exception on failure.
                       If False, logs a warning and returns False on failure.
                       
    Returns:
        bool: True if memory was successfully locked, False otherwise.
        
    Raises:
        MemoryError: If strict is True and locking fails.
    """
    try:
        # Load libc
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        
        # Call mlockall(MCL_CURRENT | MCL_FUTURE)
        result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
        
        if result != 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))
            
        logger.info("Memory successfully locked into RAM (anti-swap active).")
        return True

    except Exception as e:
        msg = f"Failed to lock memory (anti-swap disabled): {e}"
        if strict:
            logger.critical(msg)
            # Re-raise with a more specific error for the caller
            raise MemoryError(msg) from e
        else:
            logger.warning(msg)
            return False

def panic_clean():
    """
    Emergency cleanup function.
    
    Forces a full garbage collection to attempt to clear unreachable objects
    from memory immediately. This should be called before checking for
    compromise or shutting down in a hostile environment.
    """
    try:
        # Force full garbage collection
        # checking different generations
        gc.collect() 
        logger.info("Panic clean: Garbage collection forced.")
    except Exception as e:
        logger.error(f"Panic clean failed: {e}")
