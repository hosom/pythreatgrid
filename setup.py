#!/usr/bin/python

from distutils.core import setup

setup(name='pythreatgrid',
	version='0.1',
	description='Python Threatgrid API hooks.',
	author='Stephen Hosom',
	author_email='0xhosom@gmail.com',
	url='https://github.com/hosom/pythreatgrid',
	packages=['pythreatgrid'],
	install_requires=[
		'requests',
	],
	)