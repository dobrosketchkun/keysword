"""Command-line interface for Keysword."""

import argparse
import ast
import sys

def main():
    """Main entry point for Keysword CLI."""
    description = '''
USE IT ONLY IF YOU KNOW WHAT YOU ARE DOING.

  ___   _  _______  __   __  _______  _     _  _______  ______    ______  
 |   | | ||       ||  | |  ||       || | _ | ||       ||    _ |  |      | 
 |   |_| ||    ___||  |_|  ||  _____|| || || ||   _   ||   | ||  |  _    |
 |      _||   |___ |       || |_____ |       ||  | |  ||   |_||_ | | |   |
 |     |_ |    ___||_     _||_____  ||       ||  |_|  ||    __  || |_|   |
 |    _  ||   |___   |   |   _____| ||   _   ||       ||   |  | ||       |
 |___| |_||_______|  |___|  |_______||__| |__||_______||___|  |_||______| 

You can generate key pairs of Curve25519, P-256, RSA, Bitcoin, Ed25519, secp256k1, or Ethereum types from your STRONG password or any file. By using branching (similar to BIP-0032), and choosing a particular number of key pairs (up to 100 by default) in the branched state, you can defend yourself from rainbow table attacks.

Examples:

python keysword.py -k curve25519 -b '[1,4333,45453,64,99,3245]' -n 77
python keysword.py -k RSA -r 1024 -b '[410,111,123]' -n 12 -pfile myfile.bin
python keysword.py -k P-256 -b '[1,4100,4773,199,7445]' -n 168 -a 1000
python keysword.py -k curve25519 -b '[111]' -n 77 -a 10 -f separated
'''

    parser = argparse.ArgumentParser(
        add_help=True,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description,
        epilog='')

    parser.add_argument('-i', '--interactive', action="store_true", help='Launch interactive mode with TUI wizard')
    parser.add_argument('-k', '--key-type', action="store", help='Select a type of key: curve25519, P-256, RSA, bitcoin, ed25519, secp256k1, ethereum')
    parser.add_argument('-r', '--rsa-size', action="store", default=2048, help='Select a size of RSA key')
    parser.add_argument('--export-format', choices=['default', 'all', 'pem', 'der', 'openssh', 'hex', 'base64'], default='default', help='Export format for keys')
    parser.add_argument('-b', '--branches', action="store", help='Type a branching policy, in a \'[number1,...,numberX]\' format.')
    parser.add_argument('-n', '--number', action="store", help='Select the key pair number you want to use in the generated branched tree')
    parser.add_argument('-a', '--key-amount', action="store", default=1, help='Select a key amount. The larger the number, the longer it will take to generate keys (especially for RSA).')
    parser.add_argument('-f', '--save-type', action="store", default='json', help='Choose "json" to save all the keys in one file in JSON format or "separated" to save private and public keys in separate txt files.')
    parser.add_argument('-pfile', '--password-file', action="store", help='Use a file as password input (raw data of the file will be used)')
    parser.add_argument('--mnemonic', action="store_true", help='Use BIP39 mnemonic phrase as password input')
    parser.add_argument('--generate-mnemonic', action="store_true", help='Generate a new BIP39 mnemonic phrase and exit')
    parser.add_argument('--mnemonic-language', default='english', help='Language for BIP39 mnemonic (default: english)')
    
    # Encryption options
    encrypt_group = parser.add_argument_group('Encryption Options', 'Encrypt output files for additional security')
    encrypt_group.add_argument('--encrypt', action='store_true', help='Encrypt output files with AES-256-GCM')
    encrypt_group.add_argument('--decrypt-file', metavar='FILE', help='Decrypt an encrypted file')
    
    # Validation options
    validation_group = parser.add_argument_group('Validation Options', 'Verify keys and configuration')
    validation_group.add_argument('--verify', action='store_true', help='Verify generated keys without saving them')
    validation_group.add_argument('--no-warnings', action='store_true', help='Suppress password and configuration warnings')
    
    # KDF options
    kdf_group = parser.add_argument_group('Key Derivation Options', 'Configure Argon2 KDF parameters')
    kdf_group.add_argument('--preset', choices=['fast', 'balanced', 'paranoid'], help='Use Argon2 preset (fast, balanced, or paranoid)')
    kdf_group.add_argument('--time-cost', type=int, help='Argon2 time cost (iterations)')
    kdf_group.add_argument('--memory-cost', type=int, help='Argon2 memory cost in KiB')
    kdf_group.add_argument('--parallelism', type=int, help='Argon2 parallelism (number of threads)')
    
    # File handling options
    file_group = parser.add_argument_group('File Handling Options', 'Control output file behavior')
    file_group.add_argument('--force', action='store_true', help='Overwrite existing files without asking')
    file_group.add_argument('--auto-rename', action='store_true', help='Automatically rename files if they exist')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options', 'Optimize key generation speed')
    perf_group.add_argument('--parallel', action='store_true', help='Use parallel processing for multiple keys (automatic for 4+ keys)')
    perf_group.add_argument('--workers', type=int, help='Number of parallel workers (default: CPU count)')
    perf_group.add_argument('--deterministic-names', action='store_true', help='Use deterministic filenames based on configuration (reproducible naming)')

    args = parser.parse_args()

    # Handle special modes that don't use interactive TUI
    
    # Handle mnemonic generation mode
    if args.generate_mnemonic:
        from keysword.io.readers import generate_mnemonic
        
        print("Generating BIP39 mnemonic phrase...")
        print(f"Language: {args.mnemonic_language}")
        print(f"Strength: 256 bits (24 words)\n")
        
        mnemonic_phrase = generate_mnemonic(strength=256, language=args.mnemonic_language)
        
        print("=" * 70)
        print("YOUR BIP39 MNEMONIC PHRASE:")
        print("=" * 70)
        print(f"\n{mnemonic_phrase}\n")
        print("=" * 70)
        print("\n⚠ IMPORTANT:")
        print("  - Write this phrase down on paper")
        print("  - Store it in a secure location")
        print("  - Never share it with anyone")
        print("  - You can use it with --mnemonic flag to generate keys")
        print("\nExample usage:")
        print(f"  python keysword.py -k RSA -b '[1,2,3]' -n 1 --mnemonic\n")
        return

    # Handle decryption mode
    if args.decrypt_file:
        from keysword.io.encryption import decrypt_file
        import getpass
        
        print("Enter decryption password:")
        decrypt_password = getpass.getpass('')
        
        output_file = args.decrypt_file.replace('.enc', '')
        if output_file == args.decrypt_file:
            output_file = args.decrypt_file + '.decrypted'
        
        try:
            decrypt_file(args.decrypt_file, output_file, decrypt_password)
            print(f"Successfully decrypted to: {output_file}")
        except Exception as e:
            print(f"Decryption failed: {e}")
            sys.exit(1)
        return

    # All other modes: use interactive TUI with prefilled values
    from keysword.ui.interactive import interactive_mode
    
    # Build prefilled config from CLI args
    prefilled = {}
    
    if args.key_type:
        prefilled['key_type'] = args.key_type
    if args.rsa_size:
        prefilled['rsa_size'] = int(args.rsa_size)
    if args.branches:
        try:
            branches_str = args.branches.strip().strip('"').strip("'")
            branches = ast.literal_eval(branches_str)
            if not isinstance(branches, list):
                print("Error: Branches must be a list in the format [number1, number2, ...]")
                sys.exit(1)
            if not all(isinstance(b, (int, float)) for b in branches):
                print("Error: All branch values must be numbers")
                sys.exit(1)
            if len(branches) == 0:
                print("Error: Branches list cannot be empty")
                sys.exit(1)
            prefilled['branches'] = [int(b) for b in branches]
        except (ValueError, SyntaxError) as e:
            print(f'Error: Invalid branches format: {e}')
            print('Expected format: [number1, number2, ...]')
            sys.exit(1)
    if args.number:
        prefilled['key_number'] = int(args.number)
    if args.key_amount:
        prefilled['generation_count'] = int(args.key_amount)
    if args.save_type:
        prefilled['file_type'] = args.save_type
    if args.encrypt:
        prefilled['encrypt'] = True
    if args.preset:
        prefilled['preset'] = args.preset
    if args.mnemonic:
        prefilled['use_mnemonic'] = True
        prefilled['mnemonic_language'] = args.mnemonic_language
    if args.password_file:
        prefilled['password_file'] = args.password_file
    
    # Launch interactive mode with prefilled values
    interactive_mode(prefilled=prefilled)


if __name__ == '__main__':
    main()
