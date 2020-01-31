# -*- coding: utf-8 -*-

from Utils.Keys import make_me_keys
from Utils.Sup import printed, jsoned, separated
from nacl.encoding import HexEncoder as benc
from Crypto.Hash import SHA256
from Utils.Sup import sha000, clear_screen

import progressbar
import argparse
import getpass
import random
import json
import time
import sys

#Turn traceback off (0) or on (1)
sys.tracebacklimit = 1


description ='''
USE IT ONLY IF YOU KNOW WHAT ARE YOU DOING.

  ___   _  _______  __   __  _______  _     _  _______  ______    ______  
 |   | | ||       ||  | |  ||       || | _ | ||       ||    _ |  |      | 
 |   |_| ||    ___||  |_|  ||  _____|| || || ||   _   ||   | ||  |  _    |
 |      _||   |___ |       || |_____ |       ||  | |  ||   |_||_ | | |   |
 |     |_ |    ___||_     _||_____  ||       ||  |_|  ||    __  || |_|   |
 |    _  ||   |___   |   |   _____| ||   _   ||       ||   |  | ||       |
 |___| |_||_______|  |___|  |_______||__| |__||_______||___|  |_||______| 

You can generate a key pairs of curve25519, P-256, RSA or bitcoin types from you STRONG password. By using branching (basically it's BIP-0032 look-a-like rip-off) and choose a particular number of key pair (up to 100 in default) in the branched state you can defend yourself from rainbow tables attack. Curve25519 will be in hex, P-256 and RSA in PEM armor.

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

parser.add_argument('-k','--key-type', action="store", help = 'Select a type of a key (only curve25519, P-256, RSA or bitcoin are allowed)', required=True)
parser.add_argument('-r','--rsa-size', action="store",  default = 2048, help = 'Select a size of RSA key')
parser.add_argument('-b','--branches', action="store",  help = 'Type a branching policy, in a \'[number1,...,numberX]\' format.', required=True)
parser.add_argument('-n','--number', action="store", help = 'Select a number of a key pair you want to use in a generated branched tree', required=True)
parser.add_argument('-a','--key-amount', action="store",  default = 100, help = 'Select a key amount. The bigger the number, the longer it\'ll take to generate keys (mostly for RSA, like 15 min for ten 4096 bit RSA keys).')
parser.add_argument('-f', '--save-type', action="store", default='json', help = 'You can choose "json" to save all the keys in one file in json format or "separated" to save pairs in separate txt files (first - secret, second - public or address in case of bitcoin).')

args = parser.parse_args()

key_type = args.key_type
rsa_size = int(args.rsa_size)
exec('branches = ' +   args.branches)
key_number = int(args.number)
key_amount = int(args.key_amount)
file_type = args.save_type

if key_type not in ['P-256', 'curve25519', 'RSA', 'bitcoin']:
	raise ValueError('Only P-256, curve25519, RSA or bitcoin types are allowed. Your key type: ' + key_type)

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

printed(logo,time =0.001)


isPass = True
while isPass:
	clear_screen()
	print(logo)
	printed('Please enter your password:\n')
	#new_pass_first = input('')
	password = getpass.getpass('')
	clear_screen()
	print(logo)
	printed('Please enter it again:\n')
	#new_pass_second = input('')
	pass_second = getpass.getpass('')
	if password == pass_second:
		isPass = False
	else:
		clear_screen()
		print(logo)
		printed('Passwords are not the same. Try again.\n')
		time.sleep(2)


clear_screen()
print(logo)
printed('Generating your keys...\n')

all_the_keys = []


with progressbar.ProgressBar(max_value=key_amount, redirect_stdout=True) as bar:
	for num_key in range(key_amount):
		print('key', str(num_key + 1) + '/' + str(key_amount) + ':')
		bar.update(num_key+1)
		paper = str(SHA256.new(str(num_key).encode()).digest())
		password = sha000(password + paper, 50)

		salt = SHA256.new(password.encode()).digest()

		keys = make_me_keys(password  = password, salt = salt,\
							type = key_type, key_amount = key_number, \
							size_rsa = rsa_size, branches = branches)
		#print('keys', keys)
		key = dict(keys)[key_number]
		all_the_keys.append(key)
		

decoded_keys_temp_list = []


for the_key in all_the_keys:
	if key_type == 'curve25519':
		sec = benc.encode(the_key.__bytes__()).decode()
		pub = benc.encode(the_key.public_key.__bytes__()).decode()
		decoded_keys_temp_list.append({'secret' : sec, 'public' : pub})

	elif key_type == 'P-256':
		sec = the_key.export_key(format='PEM')
		pub = the_key._export_public_pem(compress = 0) #PEM
		decoded_keys_temp_list.append({'secret' : sec, 'public' : pub})

	elif key_type == 'RSA':
		sec = the_key.export_key().decode()
		pub = the_key.publickey().export_key().decode()
		decoded_keys_temp_list.append({'secret' : sec, 'public' : pub})

	elif key_type == 'bitcoin':
		from bitcoin import encode_privkey, privkey_to_address
		print('the_key',the_key)
		sec = encode_privkey(the_key[:64],'wif_compressed')
		print('sec',sec)
		addr = privkey_to_address(the_key[:64])
		print('addr',addr)
		decoded_keys_temp_list.append({'secret' : sec, 'address' : addr})


if file_type == 'json':
	jsoned(decoded_keys_temp_list, key_type)
elif file_type == 'separated':
	separated(decoded_keys_temp_list, key_type)
else:
	printed('Wrong file type. You can only use "json" and "separated" types')

clear_screen()
print(logo)
printed('\nDone.\n')
printed('\nMAKE SURE YOU INSTANTLY PUT YOUR PRIVATE KEY IN A SAFE PLACE AS IT\'S NOT ENCRYPTED!\n')
