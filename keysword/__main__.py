"""
Entry point for Keysword when run as a module or installed package.

This allows running with: python -m keysword
Or after installation: keysword
"""

from keysword.ui.cli import main

if __name__ == '__main__':
    main()

