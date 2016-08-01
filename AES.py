"""
Small script for encrypting/decrypting plaintext files.

Usage:
	python ./AES.py -ifile=encrypted.txt -ofile=decrypted.txt -dec -keyPhraseFile=secret.txt
	python ./AES.py -ifile=plaintext.txt -ofile=encrypted.txt -enc -keyPhraseFile=secret.txt

	As shown, for "-dec" a base-64 encoded file is decrypted using the key provided in secret.txt.
	For "-enc" a plaintext file is passed as input, encrypted, a key phrase read from secret.txt for the cipher key,
	and the output stored in output file.
	
	Using an external file for the key phrase just keeps the key out of the interpreter environment.
	The python interpreter does not provide for hardened security, so don't use this script for that.
"""

from __future__ import print_function
import base64
import hashlib
import sys
from Crypto import Random
from Crypto import Cipher

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def Encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(Cipher.AES.block_size)
        cipher = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def Decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:Cipher.AES.block_size]
        cipher = Cipher.AES.new(self.key, Cipher.AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[Cipher.AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def usage():
	print("Usage: python ./AES.py -ifile=[fname] -ofile=[fname] [-dec/-enc] -keyPhraseFile=[fname]")
		
def main():
	if len(sys.argv) != 5:
		print("ERROR incorrect number of arguments")
		usage()
		exit()
		
	ifile = open(sys.argv[1].split("-ifile=")[1],"r")
	ofile = open(sys.argv[2].split("-ofile=")[1],"w+")
	encrypt = sys.argv[3] == "-enc" #if true, encrypt the passed input file; if false, decrypt the input file
	phraseFile = open(sys.argv[4].split("-keyPhraseFile=")[1],"r")
	
	text = ifile.read()
	phrase = phraseFile.read().strip()
	psyfr = AESCipher(phrase)

	ifile.close()
	phraseFile.close()
	
	if encrypt:
		ofile.write(psyfr.Encrypt(text))
	else:
		ofile.write(psyfr.Decrypt(text))
	ofile.close()
	print("complete.")	
		
if __name__ == "__main__":
		main()



	
	
	
	
	
	
	
