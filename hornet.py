'''
	       NAME: Hornet Auditor
	    AUTHORS: Andrew Bassett & Matt Pudlo | NC State University
	DESCRIPTION: Evaluates Dockerfiles and Kubernetes configurations to determine their compliance
	             against the OWASP Cheat Sheet Series on Docker Security.
'''
import argparse
import re

def find_pattern(filename, pattern):
	'''
		Takes a filename as a string and a compiled regex as pattern.
		Searches file line by line ignoring blank lines and lines
		that start with the # as a comment
	'''
	matches = []
	file = open(filename, 'r')

	for line in file:
		#ignores comments and blank lines
		if len(line) > 1 and line.strip()[0] != '#': 
			matches += pattern.findall(line)

	file.close()
	print(matches)

	if len(matches) < 1:
		print('docker file did not set a user')
		return False
	else:
		print('docker file did set a user')
		return True



## MAIN


parser = argparse.ArgumentParser()
#TODO: Update this to take a list
parser.add_argument('--file', '-f', help = 'The name of file to parse')
args = parser.parse_args()

pattern = re.compile('USER')
files = []
files.append(args.file)


passed = []
failed = []

for file in files:
	print('Searching ', file, ' for set USER')
	result = find_pattern(file, pattern)
	if result:
		passed.append(file)
	else:
		failed.append(file)

print("Passed: ", passed)
print("Failed: ", failed)
