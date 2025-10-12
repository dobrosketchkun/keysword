#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Keysword - Direct usage entry point.

This allows running Keysword without installation:
    python keysword.py -k RSA -b '[1,2,3]' -n 1

For library usage, import from the keysword package:
    from keysword import generate_rsa_keys
"""

import sys

# Import the main CLI function from the package
from keysword.ui.cli import main

if __name__ == '__main__':
    sys.exit(main())

