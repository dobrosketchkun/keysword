# Keysword

Sick and tired to lose your private key or by necessity to carry it with you all the time? 

Say no more. By using this app with a novel rainbow-table-strong algorithm you can generate a key pair of your own from a password at an instant. Now *curve25519*, *P-256*, and *RSA* types are available. Further explanations in help:


```
Usage: keysword.py [-h] [-k KEY_TYPE] [-r RSA_SIZE] [-b BRANCHES] [-n NUMBER] [-a KEY_AMOUNT]

 You can generate a key pairs of curve25519, P-256 or RSA types from you STRONG password.
By using branching (basically it's BIP-0032 look-a-like rip-off) and choose a particular 
number of key pair (up to 100 in default) in branched state you can defend yourself from 
rainbow tables attack. Curve25519 will be in hex, P-256 and RSA in PEM armor.

Examples:
python keysword.py -k curve25519 -b '[1,4333,45453,64,99,3245]' -n 77
python keysword.py -k RSA -r 1024 -b '[410,111,123]' -n 12
python keysword.py -k P-256 -b '[1,4100,4773,199,7445]' -n 68 -a 1000

Arguments:
  -h, --help            show this help message and exit
  -k KEY_TYPE, --key-type KEY_TYPE
                        Select a type of a key (only curve25519, P-256 and RSA
                        are allowed)
  -r RSA_SIZE, --rsa-size RSA_SIZE
                        Select a size of RSA key
  -b BRANCHES, --branches BRANCHES
                        Type a branching policy, in a '[number1,...,numberX]'
                        format.
  -n NUMBER, --number NUMBER
                        Select a number of a key pair you want to use in a
                        generated branched tree
  -a KEY_AMOUNT, --key-amount KEY_AMOUNT
                        Select a key amount. The bigger the number, the longer
                        it'll take to generate keys (mostly for RSA, like 15
                        min for ten 4096 bit RSA keys).
  ```
