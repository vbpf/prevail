#!/usr/bin/python3
# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
import subprocess
import glob
import os.path
import os

samples_dir = 'ebpf-samples'
files = [f for f in glob.iglob(samples_dir + '/**/*.o', recursive=True)
		 if os.path.isfile(f)]

def cmd_of(*args, **kwargs):
	return ('./prevail',) + args + tuple('--'+k+'='+v for k, v in kwargs.items())

def output_of(*args, **kwargs):
	try:
		return subprocess.check_output(cmd_of(*args, **kwargs)).decode('ascii')
	except subprocess.CalledProcessError as e:
		return e.output

def call(*args, out=None, **kwargs):
	cmd = cmd_of(*args, **kwargs)
	if out:
		with open(out, 'w') as outfile:
			return subprocess.call(cmd, stdout=outfile)
	else:
		subprocess.call(cmd)

def find_sections(f):
	return output_of(f, '-l').split()

def hash_of(f, s):
	return output_of(f, s, domain='stats').split(',')[0]

print('finding sections...', end='', flush=True)
db = {
	hash_of(f, s) : (f, s)
	for f in files
	for s in find_sections(f)
}

i = 0
for (h, (f, s)) in db.items():
	i += 1
	print('\r' + ' '*60, end='\r', flush=True)
	print(i, '/', len(db), end='', flush=True)
	call(f, s, '-v', out='out/' + h)

print()
