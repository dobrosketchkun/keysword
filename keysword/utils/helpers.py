"""Helper utility functions."""

import sys
import time
import os
import platform


def printed(text, delay=0.02, chunk_size=1):
    """
    Display text with a typing effect, printing in larger chunks for better performance.
    
    Args:
        text: Text to display
        delay: Delay between chunks in seconds
        chunk_size: Number of characters per chunk
    """
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size]
        time.sleep(delay)
        sys.stdout.write(chunk)
        sys.stdout.flush()


def clear_screen():
    """
    Clears the terminal screen.
    """
    command = "cls" if platform.system().lower() == "windows" else "clear"
    os.system(command)

