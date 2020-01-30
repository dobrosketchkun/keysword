from time import sleep

import hashlib
import random
import sys
import time
import argon2
import platform
import os

def sha000(password, circles = 1, type = 'argon2'):
	'''
	Some defence from rainbow tables. Argon2 is preferable.
	'''
	
	if type == 'argon2':
		arg = argon2.low_level.hash_secret(
				password.encode(), hashlib.sha256(password.encode()).digest(),
				time_cost=1*circles, memory_cost=502400, parallelism=1, hash_len=64, 
				type=argon2.low_level.Type.ID)
		return hashlib.sha256(arg).hexdigest()
	else:
		for times in range(circles):
			cond = 1
			counter = 0
			while cond:
				sha256 = str(hashlib.sha256(password.encode()).hexdigest())
				if sha256[0:4] == '0000':
					cond = 0
					result = sha256 
				else:
					password = sha256
					counter += 1
			password = result
		return result


def printed(text, time =0.02):
	'''
	Make a cool typing effect
	'''
	for char in text:
		sleep(time)
		sys.stdout.write(char)
		sys.stdout.flush()


def jsoned(decoded_keys_temp_list, key_type):
	decoded_keys = dict(list(enumerate(decoded_keys_temp_list, start=1)))

	j_keys = json.dumps(decoded_keys, indent=2, sort_keys=True)


	printed('\nWriting your keys to the file...\n')
	time_add = str(int(time.time()))
	with open(time_add + '_' + key_type + '.json', 'w') as file:
		file.write(j_keys)

def separated(decoded_keys_temp_list, key_type):
	for keys in decoded_keys_temp_list:
		keys_text = keys['secret'] + '\n' + keys['public']
		filename = str(int(time.time())) + str(random.random()) + '_' + key_type +  '.txt'
		with open(filename,'w') as file:
			file.write(keys_text)


def clear_screen():
    """
    Clears the terminal screen.
    """

    # Clear command as function of OS
    command = "cls" if platform.system().lower()=="windows" else "clear"
    os.system(command)
