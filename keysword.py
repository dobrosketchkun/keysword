# -*- coding: utf-8 -*-
import hashlib
import argparse
import getpass
import random
import json
import time
import sys
import os
import platform
import argon2
import progressbar

from Crypto.PublicKey import ECC, RSA
from Crypto.Math.Numbers import Integer
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2

from nacl.encoding import HexEncoder as benc
from nacl.public import PrivateKey

from bitcoin import encode_privkey, privkey_to_address

def sha000(password, iterations=1, time_cost=3, memory_cost=102400, parallelism=8):
    '''
    Derive a key from the password using Argon2.
    '''
    # Since we can't use an external salt, we'll derive a salt from the password.
    # This is not ideal, but necessary given the constraints.
    salt = hashlib.sha256(password.encode()).digest()
    hash = argon2.low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost * iterations,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=argon2.low_level.Type.ID
    )
    return hash.hex()

def printed(text, delay=0.02, chunk_size=1):
    '''
    Display text with a typing effect, printing in larger chunks for better performance.
    '''
    for i in range(0, len(text), chunk_size):
        chunk = text[i:i + chunk_size]
        time.sleep(delay)
        sys.stdout.write(chunk)
        sys.stdout.flush()


def jsoned(decoded_keys_temp_list, key_type):
    '''
    Save keys in JSON format.
    '''
    decoded_keys = dict(list(enumerate(decoded_keys_temp_list, start=1)))
    j_keys = json.dumps(decoded_keys, indent=2, sort_keys=True)
    printed('\nWriting your keys to the file...\n')
    time_add = str(int(time.time()))
    with open(f"{time_add}_{key_type}.json", 'w') as file:
        file.write(j_keys)

def separated(decoded_keys_temp_list, key_type):
    '''
    Save keys in separate text files.
    '''
    for keys in decoded_keys_temp_list:
        try:
            keys_text = keys['secret'] + '\n' + keys['public']
        except KeyError:
            keys_text = keys['secret'] + '\n' + keys['address']
        filename = f"{int(time.time())}_{random.random()}_{key_type}.txt"
        with open(filename, 'w') as file:
            file.write(keys_text)

def clear_screen():
    '''
    Clears the terminal screen.
    '''
    command = "cls" if platform.system().lower() == "windows" else "clear"
    os.system(command)

def make_curve25519_keys_pbkdf2_branched(password, key_amount=1, branches=[410]):
    '''
    Generate multiple Curve25519 key pairs deterministically from a password.
    '''
    keys = []
    # Fixed iteration count for consistent security
    count = 200000
    dkLen = 32
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index)
            branch = str(branches[index % len(branches)])
            salt = (password + branch).encode()
            key_material = PBKDF2(password, salt=salt, dkLen=dkLen, count=count, hmac_hash_module=SHA256)
            keys.append(PrivateKey(key_material))
            password = key_material.hex()
    return list(enumerate(keys, start=1))

def make_p256_keys_pbkdf2_branched(password, key_amount=1, branches=[410]):
    '''
    Generate multiple P-256 key pairs deterministically from a password.
    '''
    keys = []
    count = 200000
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index)
            branch = str(branches[index % len(branches)])
            salt = (password + branch).encode()
            seed = PBKDF2(password, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            int_seed = Integer.from_bytes(seed) % ECC._curves['P-256'].order
            keys.append(ECC.construct(curve='P-256', d=int_seed))
            password = seed.hex()
    return list(enumerate(keys, start=1))


class DeterministicRandom:
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0

    def read(self, n):
        output = bytearray()
        while len(output) < n:
            counter_bytes = self.counter.to_bytes(8, 'big')
            h = HMAC.new(self.seed, counter_bytes, digestmod=SHA256)
            output.extend(h.digest())
            self.counter += 1
        return bytes(output[:n])

def make_rsa_keys_branched(password, size=2048, key_amount=1, branches=[410]):
    '''
    Generate multiple RSA key pairs deterministically from a password.
    '''
    keys = []
    count = 100000  # Reduced for performance considerations
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index)
            branch = str(branches[index % len(branches)])
            salt = (password + branch).encode()
            seed = PBKDF2(password, salt=salt, dkLen=64, count=count, hmac_hash_module=SHA256)

            # Initialize the deterministic random generator
            drbg = DeterministicRandom(seed)
            randfunc = drbg.read

            # Generate the RSA key using the deterministic randfunc
            keys.append(RSA.generate(size, randfunc=randfunc))
            password = seed.hex()
    return list(enumerate(keys, start=1))


def make_bitcoin_keys_branched(password, key_amount=1, branches=[410]):
    '''
    Generate multiple Bitcoin private keys deterministically from a password.
    '''
    keys = []
    count = 200000
    with progressbar.ProgressBar(max_value=key_amount) as bar_small:
        for index in range(key_amount):
            bar_small.update(index)
            branch = str(branches[index % len(branches)])
            salt = (password + branch).encode()
            key_material = PBKDF2(password, salt=salt, dkLen=32, count=count, hmac_hash_module=SHA256)
            keys.append(key_material.hex())
            password = key_material.hex()
    return list(enumerate(keys, start=1))

def make_me_keys(password, key_type, key_amount=1, size_rsa=2048, branches=[410]):
    '''
    Generate key pairs for the specified key type deterministically from a password.
    '''
    if key_type == 'P-256':
        return make_p256_keys_pbkdf2_branched(password=password, key_amount=key_amount, branches=branches)
    elif key_type == 'curve25519':
        return make_curve25519_keys_pbkdf2_branched(password=password, key_amount=key_amount, branches=branches)
    elif key_type == 'RSA':
        return make_rsa_keys_branched(password=password, size=size_rsa, key_amount=key_amount, branches=branches)
    elif key_type == 'bitcoin':
        return make_bitcoin_keys_branched(password=password, key_amount=key_amount, branches=branches)
    else:
        raise ValueError('Only P-256, curve25519, RSA, or bitcoin types are allowed.')

def main():
    description ='''
USE IT ONLY IF YOU KNOW WHAT YOU ARE DOING.

  ___   _  _______  __   __  _______  _     _  _______  ______    ______  
 |   | | ||       ||  | |  ||       || | _ | ||       ||    _ |  |      | 
 |   |_| ||    ___||  |_|  ||  _____|| || || ||   _   ||   | ||  |  _    |
 |      _||   |___ |       || |_____ |       ||  | |  ||   |_||_ | | |   |
 |     |_ |    ___||_     _||_____  ||       ||  |_|  ||    __  || |_|   |
 |    _  ||   |___   |   |   _____| ||   _   ||       ||   |  | ||       |
 |___| |_||_______|  |___|  |_______||__| |__||_______||___|  |_||______| 

You can generate key pairs of Curve25519, P-256, RSA, or Bitcoin types from your STRONG password. By using branching (similar to BIP-0032), and choosing a particular number of key pairs (up to 100 by default) in the branched state, you can defend yourself from rainbow table attacks. Curve25519 will be in hex, P-256 and RSA in PEM format.

Examples:

python keysword.py -k curve25519 -b '[1,4333,45453,64,99,3245]' -n 77
python keysword.py -k RSA -r 1024 -b '[410,111,123]' -n 12
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
    parser.add_argument('-f', '--save-type', action="store", default='json', help='Choose "json" to save all the keys in one file in JSON format or "separated" to save pairs in separate txt files (first - secret, second - public or address in case of Bitcoin).')

    args = parser.parse_args()

    key_type = args.key_type
    rsa_size = int(args.rsa_size)
    branches = eval(args.branches)
    key_number = int(args.number)
    key_amount = int(args.key_amount)
    file_type = args.save_type

    if key_type not in ['P-256', 'curve25519', 'RSA', 'bitcoin']:
        raise ValueError('Only P-256, curve25519, RSA, or bitcoin types are allowed. Your key type: ' + key_type)

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
    while True:
        clear_screen()
        print(logo)
        printed('Please enter your password:\n')
        password = getpass.getpass('')
        clear_screen()
        print(logo)
        printed('Please enter it again:\n')
        pass_second = getpass.getpass('')
        if password == pass_second:
            break
        else:
            clear_screen()
            print(logo)
            printed('Passwords do not match. Try again.\n')
            time.sleep(2)

    clear_screen()
    print(logo)
    printed('Generating your keys...\n')

    all_the_keys = []

    with progressbar.ProgressBar(max_value=key_amount, redirect_stdout=True) as bar:
        for num_key in range(key_amount):
            bar.update(num_key + 1)
            password = sha000(password + str(num_key), iterations=2)
            keys = make_me_keys(password=password, key_type=key_type, key_amount=key_number, size_rsa=rsa_size, branches=branches)
            key = dict(keys)[key_number]
            all_the_keys.append(key)

    decoded_keys_temp_list = []

    for the_key in all_the_keys:
        if key_type == 'curve25519':
            sec = benc.encode(the_key.__bytes__()).decode()
            pub = benc.encode(the_key.public_key.__bytes__()).decode()
            decoded_keys_temp_list.append({'secret': sec, 'public': pub})
        elif key_type == 'P-256':
            sec = the_key.export_key(format='PEM')
            pub = the_key.public_key().export_key(format='PEM')
            decoded_keys_temp_list.append({'secret': sec, 'public': pub})
        elif key_type == 'RSA':
            sec = the_key.export_key().decode()
            pub = the_key.publickey().export_key().decode()
            decoded_keys_temp_list.append({'secret': sec, 'public': pub})
        elif key_type == 'bitcoin':
            sec = encode_privkey(the_key[:64], 'wif_compressed')
            addr = privkey_to_address(the_key[:64])
            decoded_keys_temp_list.append({'secret': sec, 'address': addr})

    if file_type == 'json':
        jsoned(decoded_keys_temp_list, key_type)
    elif file_type == 'separated':
        separated(decoded_keys_temp_list, key_type)
    else:
        printed('Wrong file type. You can only use "json" and "separated" types')

    clear_screen()
    print(logo)
    printed('\nDone.\n')
    printed('\nMAKE SURE YOU SECURELY STORE YOUR PRIVATE KEYS AS THEY ARE NOT ENCRYPTED!\n')

if __name__ == '__main__':
    main()
