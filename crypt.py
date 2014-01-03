#!/usr/bin/python

import imp
import sys
import os.path

def module_exists(name):
	try:
		imp.find_module(name)
		return True
	except ImportError:
		return False

def err(msg):
	sys.stderr.write("Crypt Error: %s\n" % msg)
	quit()

# Check essential packages before running the script
modules = ["Crypto","optparse"]
for m in modules:
	if not module_exists(m):
		err("Python module %s  not installed. Try pip install %s" % (m, m))


from Crypto.PublicKey import RSA
from Crypto import Random
from optparse import OptionParser

# Constants needed for this program
PUBLIC_DEFAULT = "public.key"
PRIVATE_DEFAULT = "private.key"

# Declare the usage options
usage = "Usage: \t%prog [-d|-e] [-k key_file] INFILE OUTFILE\n\t%prog [-g]\n"
parser = OptionParser(usage)
parser.add_option("-k", "--keyfile", action="store", dest="key_file", help="your key file location")
parser.add_option("-e", "--encrypt", action="store_true", dest="encrypt", default=False, help="encrypt the input file")
parser.add_option("-d", "--decrypt", action="store_true", dest="decrypt", default=False, help="decrypt the input file")
parser.add_option("-g", "--generate", action="store_true", dest="generate", default=False, help="generate new public and private keys")
options, args = parser.parse_args()

# If we are generating keys do this first
if options.generate:
	rng = Random.new().read
	rsakey = RSA.generate(1024, rng)
	privatekey = rsakey
	publickey = rsakey.publickey()
	privkey_file = raw_input("Specify a private key file (Enter to use the defailt '%s' " % PRIVATE_DEFAULT)
	if len(privkey_file) < 1:
		privkey_file = PRIVATE_DEFAULT
	pubkey_file = raw_input("Specify a public key file (Enter to use the default '%s' " % PUBLIC_DEFAULT)
	if len(pubkey_file) < 1:
		pubkey_file = PUBLIC_DEFAULT
	privfp = open(privkey_file, "w")
	privfp.write(privatekey.exportKey())
	privfp.close()
	pubfp = open(pubkey_file, "w")
	pubfp.write(publickey.exportKey())
	pubfp.close()
	sys.stdout.write("%s and %s have been generated.\n" % (pubkey_file, privkey_file))
	quit()

# Validate the options and arguemtns
if not options.decrypt and not options.encrypt:
	parser.error('You must specify -d or -e.')
if not options.key_file:
	parser.error('You must specify a key file, -k')
if len(args) != 2:
	parser.error('You must specify an input file and an output file.')

# Load the json key file
if not os.path.isfile(options.key_file):
	err( "%s doesn't exist." % options.key_file)
file = open(options.key_file, "r")
pkey = file.read() 
file.close()

# Load the input file
if not os.path.isfile(args[0]):
	err("%s doesn't exist." % args[0])
file = open(args[0], "r")
input_data = file.read()
file.close()

# Encryption
if options.encrypt:
	# Public key encrypts, assume the key is public
	file = open(options.key_file, "r")
	publicstr = file.read()
	file.close()
	publickey = RSA.importKey(publicstr)
	enc_data = publickey.encrypt(input_data, 16)
	file = open(args[1], "w")
	file.write(enc_data[0])
	file.close()

# Decryption
if options.decrypt:
	# Private key decrypts, assume the key is private
	file = open(options.key_file, "r")
	privatestr = file.read()
	file.close()
	privatekey = RSA.importKey(privatestr)
	data = privatekey.decrypt(input_data)
	file = open(args[1], "w")
	file.write(data)
	file.close()
