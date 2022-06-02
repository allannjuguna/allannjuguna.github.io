#! /usr/bin/python3
import pickle
import os
import base64
from sys import argv as arguments

if len(arguments) < 2:
	print("Usage: de-pickler.py base64datastringhere")
	exit(-1)


def unpickle(base64datastring):
	try:
		# Convert from base64 
		b64decoded=base64.b64decode(base64datastring.encode())
		# Converting from pickle
		unpickled=pickle.loads(b64decoded)
		# Printing the result
		print(unpickled)
	except:
		print(f"Invalid base64 input string")


unpickle(arguments[1])