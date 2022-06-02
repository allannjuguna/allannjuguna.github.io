#1 /usr/bin/python3

import sys
arguments=sys.argv


def main(filename):
	try:
		with open(filename,'r') as r:
			contents=r.readlines()
			r.close()
		lines=[print("<code>"+line.strip()+"</code><br/>") for line in contents if line]
		# print(lines)

	except:
		print(f"Unable to read file")
		exit(-1)

try:
	filename=arguments[1]
	main(filename)
except:
	print(f"Usage : highlighter.py filename.txt")
	exit(-1)