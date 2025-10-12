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

    parser.add_argument('-k', '--key-type', action="store", help='Select a type of key (only curve25519, P-256, RSA, or bitcoin are allowed)', required=True)
    parser.add_argument('-r', '--rsa-size', action="store", default=2048, help='Select a size of RSA key')
    parser.add_argument('-b', '--branches', action="store", help='Type a branching policy, in a \'[number1,...,numberX]\' format.', required=True)
    parser.add_argument('-n', '--number', action="store", help='Select the key pair number you want to use in the generated branched tree', required=True)
    parser.add_argument('-a', '--key-amount', action="store", default=1, help='Select a key amount. The larger the number, the longer it will take to generate keys (especially for RSA).')
    parser.add_argument('-f', '--save-type', action="store", default='json', help='Choose "json" to save all the keys in one file in JSON format or "separated" to save private and public keys in separate txt files.')
    parser.add_argument('-pfile', '--password-file', action="store", help='Use a file as password input (raw data of the file will be used)')
    parser.add_argument('-e', '--encrypt', action="store_true", help='Encrypt output files with a password')
    parser.add_argument('--decrypt-file', action="store", help='Decrypt a previously encrypted file')
    parser.add_argument('--no-warnings', action="store_true", help='Suppress security warnings about password/branch strength')
    parser.add_argument('--force', action="store_true", help='Overwrite existing output files without prompting')
    parser.add_argument('--auto-rename', action="store_true", help='Automatically rename output files if they exist')
    parser.add_argument('--verify', action="store_true", help='Verify mode: generate and validate keys without saving them')

    args = parser.parse_args()

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

    if key_type not in ['P-256', 'curve25519', 'RSA', 'bitcoin']:
        raise ValueError('Only P-256, curve25519, RSA, or bitcoin types are allowed. Your key type: ' + key_type)
    
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
    if password_file:
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

    clear_screen()
    print(logo)
    printed('Generating your keys...\n')

    all_the_keys = []

    with progressbar.ProgressBar(max_value=key_amount, redirect_stdout=True) as bar:
        for num_key in range(key_amount):
            bar.update(num_key + 1)
            if isinstance(password, str):
                password_bytes = password.encode()
            else:
                password_bytes = password
            password_hash = derive_key(password_bytes + str(num_key).encode(), iterations=2)
            password = password_hash  # password is bytes
            keys = make_me_keys(password=password, key_type=key_type, key_amount=key_number, size_rsa=rsa_size, branches=branches)
            key = dict(keys)[key_number]
            all_the_keys.append(key)

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

    for the_key in all_the_keys:
        if key_type == 'curve25519':
            sec = benc.encode(the_key.__bytes__()).decode()
            pub = benc.encode(the_key.public_key.__bytes__()).decode()
            decoded_keys_temp_list.append({'secret': sec, 'public': pub})
        elif key_type == 'P-256':
            sec = the_key.export_key(format='PEM').decode()
            pub = the_key.public_key().export_key(format='PEM').decode()
            decoded_keys_temp_list.append({'secret': sec, 'public': pub})
        elif key_type == 'RSA':
            sec = the_key.export_key().decode()
            pub = the_key.publickey().export_key().decode()
            decoded_keys_temp_list.append({'secret': sec, 'public': pub})
        elif key_type == 'bitcoin':
            # the_key is a hex string (64 chars = 32 bytes)
            # [:64] extracts the first 64 hex characters representing the 32-byte private key
            sec = encode_privkey(the_key[:64], 'wif_compressed')
            addr = privkey_to_address(the_key[:64])
            decoded_keys_temp_list.append({'secret': sec, 'address': addr})

    if file_type == 'json':
        jsoned(decoded_keys_temp_list, key_type, encrypt=args.encrypt, force=args.force, auto_rename=args.auto_rename)
    elif file_type == 'separated':
        separated(decoded_keys_temp_list, key_type, encrypt=args.encrypt, force=args.force, auto_rename=args.auto_rename)
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

