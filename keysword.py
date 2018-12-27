# -*- coding: utf-8 -*-

from Utils.Keys import make_me_keys
from Utils.Sup import printed
from nacl.encoding import HexEncoder as benc

import argparse
import getpass
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

You can generate a key pairs of curve25519, P-256 or RSA types from you STRONG password.By using branching (basically it's BIP-0032 look-a-like rip-off) and choose a particular number of key pair (up to 100 in default) in branched state you can defend yourself from rainbow tables attack. Curve25519 will be in hex, P-256 and RSA in PEM armor.

Examples:

python keysword.py -k curve25519 -b '[1,4333,45453,64,99,3245]' -n 77
python keysword.py -k RSA -r 1024 -b '[410,111,123]' -n 12
python keysword.py -k P-256 -b '[1,4100,4773,199,7445]' -n 168 -a 1000

'''

parser = argparse.ArgumentParser(
    add_help=True,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=description,
	epilog='')

parser.add_argument('-k','--key-type', action="store", help = 'Select a type of a key (only curve25519, P-256 and RSA are allowed)')
parser.add_argument('-r','--rsa-size', action="store",  default = 2048, help = 'Select a size of RSA key')
parser.add_argument('-b','--branches', action="store",  help = 'Type a branching policy, in a \'[number1,...,numberX]\' format.')
parser.add_argument('-n','--number', action="store", help = 'Select a number of a key pair you want to use in a generated branched tree')
parser.add_argument('-a','--key-amount', action="store",  default = 100, help = 'Select a key amount. The bigger the number, the longer it\'ll take to generate keys (mostly for RSA, like 15 min for ten 4096 bit RSA keys).')
args = parser.parse_args()

key_type = args.key_type
rsa_size = int(args.rsa_size)
exec('branches = ' +   args.branches)
key_number = int(args.number)
key_amount = int(args.key_amount)



ps = 1
while ps:	
	printed('\nPlease enter your password:\n')
	#new_pass_first = input('')
	password = getpass.getpass('')
	printed('Please enter it again.\n')
	#new_pass_second = input('')
	pass_second = getpass.getpass('')
	if password == pass_second:
		ps = 0
	else:
		printed('Passwords are not the same. Try again.\n')

printed('Generating your keys...\n')
keys = make_me_keys(password  = password, type = key_type, key_amount = key_amount, size_rsa = rsa_size, branches = branches)
key = dict(keys)[key_number]

if key_type == 'curve25519':
	sec = benc.encode(key.__bytes__()).decode()
	pub = benc.encode(key.public_key.__bytes__()).decode()

elif key_type == 'P-256':
	sec = key.export_key(format='PEM')
	pub = key._export_public_pem(compress = 0) #PEM

elif key_type == 'RSA':
	sec = key.export_key().decode()
	pub = key.publickey().export_key().decode()

else:
	print('How do you manage to do this?')

printed('\nWriting your keys to the file...\n')
time_add = str(int(time.time()))
with open(time_add + '_' + key_type + '.priv', 'w') as file:
	file.write(sec)

with open(time_add + '_' + key_type + '.pub', 'w') as file:
	file.write(pub)

printed('\nDone.\n')
printed('\nMAKE SURE YOU INSTANTLY PUT YOUR PRIVATE KEY IN A SAFE PLACE AS IT\'S NOT ENCRYPTED!')
