"""Command-line interface for Keysword."""

import argparse
import ast
import sys
import time
import progressbar

from nacl.encoding import HexEncoder as benc
from bitcoin import encode_privkey, privkey_to_address

from keysword.core.kdf import derive_key
from keysword.core.generators import make_me_keys
from keysword.io.readers import read_password_with_confirmation, read_password_from_file
from keysword.io.writers import jsoned, separated
from keysword.utils.helpers import printed, clear_screen


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

You can generate key pairs of Curve25519, P-256, RSA, or Bitcoin types from your STRONG password or any file. By using branching (similar to BIP-0032), and choosing a particular number of key pairs (up to 100 by default) in the branched state, you can defend yourself from rainbow table attacks. Curve25519 will be in hex, P-256 and RSA in PEM format.

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

    parser.add_argument('-k', '--key-type', action="store", help='Select a type of key: curve25519, P-256, RSA, bitcoin, ed25519, secp256k1, ethereum', required=True)
    parser.add_argument('-r', '--rsa-size', action="store", default=2048, help='Select a size of RSA key')
    parser.add_argument('--export-format', choices=['default', 'all', 'pem', 'der', 'openssh', 'hex', 'base64'], default='default', help='Export format for keys (default: standard format for key type, all: export all available formats)')
    parser.add_argument('-b', '--branches', action="store", help='Type a branching policy, in a \'[number1,...,numberX]\' format.', required=True)
    parser.add_argument('-n', '--number', action="store", help='Select the key pair number you want to use in the generated branched tree', required=True)
    parser.add_argument('-a', '--key-amount', action="store", default=1, help='Select a key amount. The larger the number, the longer it will take to generate keys (especially for RSA).')
    parser.add_argument('-f', '--save-type', action="store", default='json', help='Choose "json" to save all the keys in one file in JSON format or "separated" to save private and public keys in separate txt files.')
    parser.add_argument('-pfile', '--password-file', action="store", help='Use a file as password input (raw data of the file will be used)')
    parser.add_argument('--mnemonic', action="store_true", help='Use BIP39 mnemonic phrase as password input')
    parser.add_argument('--generate-mnemonic', action="store_true", help='Generate a new BIP39 mnemonic phrase and exit')
    parser.add_argument('--mnemonic-language', default='english', help='BIP39 mnemonic language (default: english)')
    parser.add_argument('-e', '--encrypt', action="store_true", help='Encrypt output files with a password')
    parser.add_argument('--decrypt-file', action="store", help='Decrypt a previously encrypted file')
    parser.add_argument('--no-warnings', action="store_true", help='Suppress security warnings about password/branch strength')
    parser.add_argument('--force', action="store_true", help='Overwrite existing output files without prompting')
    parser.add_argument('--auto-rename', action="store_true", help='Automatically rename output files if they exist')
    parser.add_argument('--verify', action="store_true", help='Verify mode: generate and validate keys without saving them')
    
    # Argon2 KDF parameters
    argon2_group = parser.add_argument_group('Argon2 KDF Options', 'Configure key derivation function parameters')
    argon2_group.add_argument('--preset', choices=['fast', 'balanced', 'paranoid'], help='Use Argon2 preset: fast (32MB), balanced (100MB, default), paranoid (1GB)')
    argon2_group.add_argument('--time-cost', type=int, help='Argon2 time cost parameter (default: 3)')
    argon2_group.add_argument('--memory-cost', type=int, help='Argon2 memory cost in KiB (default: 102400)')
    argon2_group.add_argument('--parallelism', type=int, help='Argon2 parallelism parameter (default: 8)')
    
    # Performance options
    perf_group = parser.add_argument_group('Performance Options', 'Optimize key generation speed')
    perf_group.add_argument('--parallel', action='store_true', help='Use parallel processing for multiple keys (automatic for 4+ keys)')
    perf_group.add_argument('--workers', type=int, help='Number of parallel workers (default: CPU count)')
    perf_group.add_argument('--deterministic-names', action='store_true', help='Use deterministic filenames based on configuration (reproducible naming)')

    args = parser.parse_args()

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

    key_type = args.key_type
    rsa_size = int(args.rsa_size)
    
    # Safely parse branches list - use ast.literal_eval instead of eval for security
    try:
        # Strip any surrounding quotes that might be passed from the shell
        branches_str = args.branches.strip().strip('"').strip("'")
        branches = ast.literal_eval(branches_str)
        if not isinstance(branches, list):
            raise ValueError('Branches must be a list in the format [number1, number2, ...]')
        if not all(isinstance(b, (int, float)) for b in branches):
            raise ValueError('All branch values must be numbers')
        if len(branches) == 0:
            raise ValueError('Branches list cannot be empty')
    except (ValueError, SyntaxError) as e:
        raise ValueError(f'Invalid branches format: {e}. Expected format: [number1, number2, ...]')
    
    key_number = int(args.number)
    key_amount = int(args.key_amount)
    file_type = args.save_type
    password_file = args.password_file

    if key_type not in ['P-256', 'curve25519', 'RSA', 'bitcoin', 'ed25519', 'secp256k1', 'ethereum']:
        raise ValueError(f'Unsupported key type: {key_type}. Supported types: P-256, curve25519, RSA, bitcoin, ed25519, secp256k1, ethereum')
    
    # Validate branches configuration
    if not args.no_warnings:
        from keysword.validation.input_validators import validate_branches, validate_key_number
        
        is_strong_branches, branches_msg = validate_branches(branches)
        if not is_strong_branches:
            print(f"\n⚠ Branch Configuration Warning: {branches_msg}")
        
        is_valid_key_num, key_num_msg = validate_key_number(key_number, branches)
        if not is_valid_key_num:
            print(f"\n⚠ Key Number Warning: {key_num_msg}")

    clear_screen()
    logo = '''
  ___   _  _______  __   __  _______  _     _  _______  ______    ______  
 |   | | ||       ||  | |  ||       || | _ | ||       ||    _ |  |      | 
 |   |_| ||    ___||  |_|  ||  _____|| || || ||   _   ||   | ||  |  _    |
 |      _||   |___ |       || |_____ |       ||  | |  ||   |_||_ | | |   |
 |     |_ |    ___||_     _||_____  ||       ||  |_|  ||    __  || |_|   |
 |    _  ||   |___   |   |   _____| ||   _   ||       ||   |  | ||       |
 |___| |_||_______|  |___|  |_______||__| |__||_______||___|  |_||______| 
'''

    printed(logo, delay=0.01, chunk_size=10)

    # Password input with confirmation
    if args.mnemonic:
        # Use BIP39 mnemonic as password source
        from keysword.io.readers import read_mnemonic
        
        clear_screen()
        print(logo)
        printed('Using BIP39 mnemonic phrase as password source.\n')
        
        try:
            password = read_mnemonic(language=args.mnemonic_language)
            clear_screen()
            print(logo)
            printed('Mnemonic phrase validated successfully.\n')
            printed(f'Derived 512-bit seed from mnemonic.\n')
        except ValueError as e:
            clear_screen()
            print(logo)
            printed(f'Error: {e}\n')
            sys.exit(1)
        except Exception as e:
            clear_screen()
            print(logo)
            printed(f'Unexpected error: {e}\n')
            sys.exit(1)
    elif password_file:
        try:
            password = read_password_from_file(password_file)
            clear_screen()
            print(logo)
            printed('Password has been read from the file successfully.\n')
        except Exception as e:
            clear_screen()
            print(logo)
            printed(f'Error reading password file: {e}\n')
            sys.exit(1)
    else:
        while True:
            clear_screen()
            print(logo)
            printed('Please enter your password:\n')
            password = read_password_with_confirmation()
            
            # Validate password strength
            if not args.no_warnings:
                from keysword.validation.input_validators import validate_password_strength
                is_strong, warning_msg, details = validate_password_strength(password.decode('utf-8', errors='ignore'))
                
                if not is_strong:
                    print(f"\n⚠ Password Strength Warning:")
                    print(f"  {warning_msg}")
                    print(f"  Length: {details['length']} characters")
                    print(f"  Entropy: {details['entropy']:.1f} bits")
                    print("\nA weak password may be vulnerable to brute-force attacks.")
                    proceed = input("Continue anyway? (y/N): ").strip().lower()
                    if proceed != 'y':
                        continue
            
            break

    # Prepare Argon2 KDF parameters
    kdf_params = {}
    if args.preset:
        kdf_params['preset'] = args.preset
        from keysword.core.kdf import ARGON2_PRESETS
        preset_info = ARGON2_PRESETS[args.preset]
        if not args.no_warnings:
            print(f"\nUsing Argon2 preset: {args.preset}")
            print(f"  {preset_info['description']}")
            print(f"  Time: {preset_info['time_cost']}, Memory: {preset_info['memory_cost']} KiB, Parallelism: {preset_info['parallelism']}\n")
    else:
        if args.time_cost:
            kdf_params['time_cost'] = args.time_cost
        if args.memory_cost:
            kdf_params['memory_cost'] = args.memory_cost
        if args.parallelism:
            kdf_params['parallelism'] = args.parallelism
        
        if kdf_params and not args.no_warnings:
            print("\nUsing custom Argon2 parameters:")
            if 'time_cost' in kdf_params:
                print(f"  Time cost: {kdf_params['time_cost']}")
            if 'memory_cost' in kdf_params:
                print(f"  Memory cost: {kdf_params['memory_cost']} KiB")
            if 'parallelism' in kdf_params:
                print(f"  Parallelism: {kdf_params['parallelism']}")
            print()
    
    clear_screen()
    print(logo)
    printed('Generating your keys...\n')

    all_the_keys = []

    # Determine if parallel processing should be used
    from keysword.core.parallel import should_use_parallel, generate_keys_parallel
    use_parallel = args.parallel or should_use_parallel(key_amount, key_type)
    
    # Check if key type supports parallel processing (Windows limitation)
    unpicklable_types = ['RSA', 'P-256', 'secp256k1']
    if use_parallel and key_type in unpicklable_types:
        if not args.no_warnings:
            print(f"⚠ Warning: Parallel processing not supported for {key_type} keys on Windows.")
            print(f"  Reason: These key objects cannot be pickled for multiprocessing.")
            print(f"  Falling back to sequential generation...\n")
        use_parallel = False
    
    if use_parallel and key_amount > 1:
        # Use parallel processing
        num_workers = args.workers if args.workers else None
        if not args.no_warnings:
            import multiprocessing as mp
            actual_workers = num_workers if num_workers else min(mp.cpu_count(), key_amount)
            print(f"Using parallel processing with {actual_workers} workers...\n")
        
        # Progress callback for tqdm
        try:
            from tqdm import tqdm
            pbar = tqdm(total=key_amount, desc="Generating keys", unit="key")
            
            def progress_callback(current, total):
                pbar.update(1)
            
            all_the_keys = generate_keys_parallel(
                password=password,
                key_type=key_type,
                key_amount=key_amount,
                branches=branches,
                key_number=key_number,
                rsa_size=rsa_size,
                num_workers=num_workers,
                kdf_params=kdf_params,
                progress_callback=progress_callback
            )
            pbar.close()
        except ImportError:
            # Fall back to progressbar if tqdm not available
            print("Generating keys in parallel...")
            all_the_keys = generate_keys_parallel(
                password=password,
                key_type=key_type,
                key_amount=key_amount,
                branches=branches,
                key_number=key_number,
                rsa_size=rsa_size,
                num_workers=num_workers,
                kdf_params=kdf_params
            )
    else:
        # Sequential generation with enhanced progress bar
        from keysword.utils.progress import EnhancedProgressBar
        
        with EnhancedProgressBar(key_amount, desc="Generating keys", unit="key") as pbar:
            for num_key in range(key_amount):
                if isinstance(password, str):
                    password_bytes = password.encode()
                else:
                    password_bytes = password
                password_hash = derive_key(password_bytes + str(num_key).encode(), iterations=2, **kdf_params)
                password = password_hash  # password is bytes
                keys = make_me_keys(password=password, key_type=key_type, key_amount=key_number, size_rsa=rsa_size, branches=branches)
                key = dict(keys)[key_number]
                all_the_keys.append(key)
                pbar.update(1)

    # Verify mode: validate keys without saving
    if args.verify:
        from keysword.validation.key_validators import verify_key
        
        clear_screen()
        print(logo)
        printed('\n=== VERIFICATION MODE ===\n')
        printed(f'Validating {len(all_the_keys)} generated key(s)...\n\n')
        
        all_valid = True
        for idx, the_key in enumerate(all_the_keys, start=1):
            is_valid, message = verify_key(the_key, key_type)
            status = "✓" if is_valid else "✗"
            print(f"{status} Key {idx}/{len(all_the_keys)}: {message}")
            if not is_valid:
                all_valid = False
        
        print("\n" + "="*50)
        if all_valid:
            printed('\n✓ All keys are valid!\n')
            printed('Keys were NOT saved (verify mode).\n')
        else:
            printed('\n✗ Some keys failed validation!\n')
        
        return

    decoded_keys_temp_list = []

    # Handle export format option
    if args.export_format == 'all':
        # Export all available formats using KeyFormatter
        from keysword.core.formats import KeyFormatter
        
        for the_key in all_the_keys:
            formats = KeyFormatter.export_key(the_key, key_type)
            decoded_keys_temp_list.append(formats)
    else:
        # Use default or specified format
        for the_key in all_the_keys:
            if key_type == 'curve25519':
                if args.export_format == 'hex' or args.export_format == 'default':
                    sec = benc.encode(the_key.__bytes__()).decode()
                    pub = benc.encode(the_key.public_key.__bytes__()).decode()
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
                elif args.export_format == 'base64':
                    from nacl.encoding import Base64Encoder
                    sec = Base64Encoder.encode(the_key.__bytes__()).decode()
                    pub = Base64Encoder.encode(the_key.public_key.__bytes__()).decode()
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
            elif key_type == 'P-256' or key_type == 'secp256k1':
                if args.export_format in ['pem', 'default']:
                    sec_bytes = the_key.export_key(format='PEM')
                    pub_bytes = the_key.public_key().export_key(format='PEM')
                    sec = sec_bytes.decode() if isinstance(sec_bytes, bytes) else sec_bytes
                    pub = pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
                elif args.export_format == 'der':
                    sec = the_key.export_key(format='DER').hex()
                    pub = the_key.public_key().export_key(format='DER').hex()
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
                elif args.export_format == 'openssh':
                    sec_bytes = the_key.export_key(format='PEM')
                    pub_bytes = the_key.public_key().export_key(format='OpenSSH')
                    sec = sec_bytes.decode() if isinstance(sec_bytes, bytes) else sec_bytes
                    pub = pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
            elif key_type == 'RSA':
                if args.export_format in ['pem', 'default']:
                    sec_bytes = the_key.export_key()
                    pub_bytes = the_key.publickey().export_key()
                    sec = sec_bytes.decode() if isinstance(sec_bytes, bytes) else sec_bytes
                    pub = pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
                elif args.export_format == 'der':
                    sec = the_key.export_key(format='DER').hex()
                    pub = the_key.publickey().export_key(format='DER').hex()
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
                elif args.export_format == 'openssh':
                    sec_bytes = the_key.export_key()
                    pub_bytes = the_key.publickey().export_key(format='OpenSSH')
                    sec = sec_bytes.decode() if isinstance(sec_bytes, bytes) else sec_bytes
                    pub = pub_bytes.decode() if isinstance(pub_bytes, bytes) else pub_bytes
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
            elif key_type == 'bitcoin':
                # the_key is a hex string (64 chars = 32 bytes)
                sec = encode_privkey(the_key[:64], 'wif_compressed')
                addr = privkey_to_address(the_key[:64])
                decoded_keys_temp_list.append({'secret': sec, 'address': addr})
            elif key_type == 'ed25519':
                if args.export_format == 'hex' or args.export_format == 'default':
                    sec = benc.encode(the_key.__bytes__()).decode()
                    pub = benc.encode(the_key.verify_key.__bytes__()).decode()
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
                elif args.export_format == 'base64':
                    from nacl.encoding import Base64Encoder
                    sec = Base64Encoder.encode(the_key.__bytes__()).decode()
                    pub = Base64Encoder.encode(the_key.verify_key.__bytes__()).decode()
                    decoded_keys_temp_list.append({'secret': sec, 'public': pub})
            elif key_type == 'ethereum':
                # the_key is a dict with 'key' (hex string) and 'address' (0x...)
                sec = the_key['key']  # Already a hex string
                addr = the_key['address']
                decoded_keys_temp_list.append({'secret': sec, 'address': addr})

    if file_type == 'json':
        jsoned(decoded_keys_temp_list, key_type, encrypt=args.encrypt, force=args.force, auto_rename=args.auto_rename,
               deterministic_names=args.deterministic_names, branches=branches, key_number=key_number, key_amount=key_amount)
    elif file_type == 'separated':
        separated(decoded_keys_temp_list, key_type, encrypt=args.encrypt, force=args.force, auto_rename=args.auto_rename,
                  deterministic_names=args.deterministic_names, branches=branches, key_number=key_number, key_amount=key_amount)
    else:
        printed('Wrong file type. You can only use "json" and "separated" types')

    clear_screen()
    print(logo)
    printed('\nDone.\n')
    if args.encrypt:
        printed('\nYour keys have been encrypted. Remember your encryption password!\n')
    else:
        printed('\nMAKE SURE YOU SECURELY STORE YOUR PRIVATE KEYS AS THEY ARE NOT ENCRYPTED!\n')


if __name__ == '__main__':
    main()

