#!/usr/bin/env python3
"""Test runner script for Keysword."""

import sys
import subprocess
import argparse


def main():
    """Run tests with various options."""
    parser = argparse.ArgumentParser(description='Run Keysword tests')
    parser.add_argument('--coverage', '-c', action='store_true',
                        help='Run with coverage report')
    parser.add_argument('--html', action='store_true',
                        help='Generate HTML coverage report')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--fast', '-f', action='store_true',
                        help='Skip slow tests')
    parser.add_argument('--integration', '-i', action='store_true',
                        help='Run only integration tests')
    parser.add_argument('--file', type=str,
                        help='Run specific test file (e.g., test_kdf.py)')
    parser.add_argument('--test', type=str,
                        help='Run specific test (e.g., TestKDF::test_derive_key_deterministic)')
    parser.add_argument('--stop', '-x', action='store_true',
                        help='Stop on first failure')
    
    args = parser.parse_args()
    
    # Build pytest command
    cmd = ['python', '-m', 'pytest']
    
    # Add test path
    if args.file:
        cmd.append(f'tests/{args.file}')
    elif args.test:
        cmd.append(f'tests/{args.test}')
    else:
        cmd.append('tests/')
    
    # Add options
    if args.verbose:
        cmd.append('-vv')
    else:
        cmd.append('-v')
    
    if args.stop:
        cmd.append('-x')
    
    if args.fast:
        cmd.extend(['-m', 'not slow'])
    
    if args.integration:
        cmd.extend(['-m', 'integration'])
    
    if args.coverage:
        cmd.extend(['--cov=keysword', '--cov-report=term'])
        if args.html:
            cmd.append('--cov-report=html')
    
    # Add default options
    cmd.append('--tb=short')
    
    # Print command
    print(f"Running: {' '.join(cmd)}\n")
    
    # Run tests
    result = subprocess.run(cmd)
    
    if args.coverage and args.html:
        print("\n✅ Coverage report generated at: htmlcov/index.html")
    
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())

