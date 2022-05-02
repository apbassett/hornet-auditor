'''
	       NAME: Hornet Auditor
	    AUTHORS: Andrew Bassett & Matt Pudlo | NC State University
	DESCRIPTION: Evaluates Dockerfiles and Kubernetes configurations to determine their compliance
	             against the OWASP Cheat Sheet Series on Docker Security.
'''
import argparse
import re
from pathlib import Path

# Default root directory location to search for files from
DEFAULT_ROOT_DIR = './'

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
		if len(line.strip()) > 1 and line.strip()[0] != '#': 
			matches += pattern.findall(line)

	file.close()

	if len(matches) < 1:
		return False
	print(f'Found matches: {matches} in {filename}')
	return True


def compliant(dockerfiles, yamls, pattern, eval_docker=False, eval_yamls=False):
	'''
		Evaluate whether the given pattern exists in all of the specified Dockerfiles, or in
		any of the specified Kubernetes yaml files.
	'''
	if eval_yamls:
		for yaml in yamls:
			if find_pattern(yaml, pattern):
				break
		else:
			return False	
	else:
		for dockerfile in dockerfiles:
			if not find_pattern(dockerfile, pattern):
				return False
	return True


def locate_files(docker_dir, k8s_dir):
	'''
		Search all subdirectories of the given paths and return a tuple of lists containing
		Dockerfiles and Kubernetes yamls to parse.
	'''
	dockerfiles = list(Path(docker_dir).rglob('Dockerfile')) 
	k8s_yamls = list(Path(docker_dir).rglob('*.y*ml'))
	return dockerfiles, k8s_yamls


def main(docker_dir, k8s_dir):
	''' Main function '''
	# Meta variables
	dockerfiles, yamls = locate_files(docker_dir, k8s_dir)
	results = []

	##########
	# RULE 2 #
	##########
	pattern = re.compile('USER')
	if not compliant(dockerfiles, yamls, pattern, eval_docker=True):
		results.append(dict(rule_2=False))
	else:
		results.append(dict(rule_2=True))

	##########
	# RULE 3 #
	##########
	pattern = re.compile('capabilities:')
	if not compliant(dockerfiles, yamls, pattern, eval_yamls=True):
		results.append(dict(rule_3=False))
	else:
		results.append(dict(rule_3=True))

	##########
	# RULE 4 #
	##########
	pattern = re.compile('allowPrivilegeEscalation: false')
	if not compliant(dockerfiles, yamls, pattern, eval_yamls=True):
		results.append(dict(rule_4=False))
	else:
		results.append(dict(rule_4=True))

	##########
	# RULE 7 #
	##########
	pattern = re.compile('limits:')
	if not compliant(dockerfiles, yamls, pattern, eval_yamls=True):
		results.append(dict(rule_7=False))
	else:
		results.append(dict(rule_7=True))

	##########
	# RULE 8 #
	##########
	pattern = re.compile('readOnlyRootFilesystem: true')
	if not compliant(dockerfiles, yamls, pattern, eval_yamls=True):
		results.append(dict(rule_8=False))
	else:
		results.append(dict(rule_8=True))

	# Results
	for rule in results:
		print(rule)


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	# Dockerfile(s) root directory
	parser.add_argument(
		'--docker-dir',
		'-d',
		default=DEFAULT_ROOT_DIR,
		help='The root dir of any Dockerfiles to parse'
	)
	# Kubernetes yamls root directory
	parser.add_argument(
		'--k8s-dir', '-k',
		default=DEFAULT_ROOT_DIR,
		help='The root dir of any Kubernetes config files to parse'
	)
	args = parser.parse_args()
	main(args.docker_dir, args.k8s_dir)
