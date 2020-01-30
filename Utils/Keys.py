from Crypto.PublicKey import ECC, RSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from nacl.encoding import HexEncoder as benc
from nacl.public import PrivateKey, PublicKey
from Crypto.Protocol.KDF import PBKDF2
import progressbar

try:
	from .Sup import sha000
except:
	from Sup import sha000

	
def make_curve25519_keys_pbkdf2_branched(password, salt, key_amount = 1, branches = [410]):
	'''
	Make multiple key pairs at once, eather P-256 or curve25519 from any string.
	Brances implements additional layer of security. Branch is better be an integer, but, for real, it may be any string
	Returns a list
	'''
	# password = sha000(password, 50)
	# salt = SHA256.new(password.encode()).digest()
	#print('salt',benc.encode(salt))
	count = int(str(int(benc.encode(salt),16))[0:5])

	dkLen = 32
	
	keys = []
	with progressbar.ProgressBar(max_value=key_amount) as bar_small:
		for tymes in range(key_amount):
			bar_small.update(tymes)
			#sha256 = SHA256.new(password)
			#count = int(str(int(benc.encode(sha256.digest()),16))[0:5])
			#print(branches[tymes%len(branches)])
			key = PBKDF2(password, salt = (str(salt) + str(branches[tymes%len(branches)])), dkLen = dkLen, count = count)
			keys.append(PrivateKey(benc.encode(key), encoder=benc))
			password = key
	return list(enumerate(keys, start=1))	
	
	
def make_p256_keys_pbkdf2_branched(password, salt, key_amount = 1, branches = [410]):
	'''
	Make P-256 multiple key pairs at once from any string
	Brances implements additional layer of security. Branch is better be an integer, but, for real, it may be any string	
	Returns a list
	'''
	# password = sha000(password, 50)
	# salt = SHA256.new(password.encode()).digest()
	#print('salt',benc.encode(salt))
	count = int(str(int(benc.encode(salt),16))[0:5])

	master_key = PBKDF2(password, salt = str(salt), count=count) 
	
	def my_rand(n):
		my_rand.counter += 1
		return PBKDF2(master_key, "my_rand:%d" % my_rand.counter, dkLen=n, count=1)
	my_rand.counter = 0
	
	keys = []
	with progressbar.ProgressBar(max_value=key_amount) as bar_small:
		for tymes in range(key_amount):
			bar_small.update(tymes)
			key = PBKDF2(password, salt = (str(salt) + str(branches[tymes%len(branches)])), count = count)
			keys.append(ECC.generate(curve = 'P-256', randfunc=my_rand))
			password = key
	return list(enumerate(keys, start=1))	
	
	
def make_rsa_keys_branched(password, salt, size = 2048, key_amount = 1, branches = [410]):
	'''
	Make RSA key pairs from any string.
	Brances implements additional layer of security. Branch is better be an integer, but, for real, it may be any string	
	Returns a list
	'''
	# password = sha000(password, 50)
	keys = []
	# sha256 = str(SHA256.new(password.encode()).digest())	
	sha256 = salt
	def my_rand(n):
		my_rand.counter += 1
		return PBKDF2(master_key, "my_rand:%d" % my_rand.counter, dkLen=n, count=1)

	my_rand.counter = 0
	with progressbar.ProgressBar(max_value=key_amount) as bar_small:
		for tymes in range(key_amount):
			bar_small.update(tymes)
			master_key = PBKDF2(password, salt = (str(sha256) + str(branches[tymes%len(branches)])), count=10000) 
			keys.append(RSA.generate(size, randfunc=my_rand)) 
			password = keys[-1].export_key('PEM').decode()
	return list(enumerate(keys, start=1))	
	


def make_bitcoin_keys_branched(password, salt, key_amount = 1, branches = [410]):
	'''
	Make multiple bitcoin private keys at once from any string
	Brances implements additional layer of security. Branch is better be an integer, but, for real, it may be any string
	Returns a list
	'''
	# password = sha000(password, 50)
	# salt = SHA256.new(password.encode()).digest()
	#print('salt',benc.encode(salt))
	count = int(str(int(benc.encode(salt),16))[0:5])

	master_key = PBKDF2(password, salt = str(salt), count=count) 
	
	def my_rand(n):
		my_rand.counter += 1
		return PBKDF2(master_key, "my_rand:%d" % my_rand.counter, dkLen=n, count=1)
	my_rand.counter = 0
	
	keys = []
	with progressbar.ProgressBar(max_value=key_amount) as bar_small:
		for tymes in range(key_amount):
			bar_small.update(tymes)
			key = PBKDF2(password,dkLen=64, salt = (str(salt) + str(branches[tymes%len(branches)])), count = count)
			#keys.append(ECC.generate(curve = 'P-256', randfunc=my_rand))
			keys.append(key.hex())
			password = key
	return list(enumerate(keys, start=1))



def make_me_keys(password, salt, type, key_amount = 1, size_rsa = 2048, branches = [410]):
	'''
	Make key pairs for RSA, P-256 or curve25519 in amounts from any string
	Brances implements additional layer of security. Branch is better be an integer, but, for real, it may be any string	
	Returns a list
	'''
	if type == 'P-256':
		return make_p256_keys_pbkdf2_branched(password=password, salt=salt, key_amount = key_amount, branches = branches)
	elif type == 'curve25519':
		return make_curve25519_keys_pbkdf2_branched(password=password, salt=salt, key_amount = key_amount, branches = branches)
	elif type == 'RSA':
		return make_rsa_keys_branched(password=password, salt=salt, size = size_rsa, key_amount = key_amount, branches = branches)
	elif type == 'bitcoin':
		return make_bitcoin_keys_branched(password=password, salt=salt, key_amount = key_amount, branches = branches)
	else:
		print('type:', type,'\n')
		raise ValueError('Only P-256, curve25519, RSA or bitcoin types are allowed.')	
