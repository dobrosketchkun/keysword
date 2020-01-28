import hashlib
import sys
from time import sleep
import argon2

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
