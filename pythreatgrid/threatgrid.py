#!/usr/bin/env python3

import sys
import requests
import copy
import json

## Suppress urllib error messages. Find a better way to handle this
## later.

import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

## Check and verify the version of requests in use. This code is only
## tested and verified with requests 2.9 and greater

_HOST = 'https://panacea.threatgrid.com'
'''str: Represents the host that the API will connect to.
'''
_APIROOT = '/api/v2'
'''str: The root URI for the API.
'''
_URL = _HOST + _APIROOT
'''str: Controls where requests will be sent.
'''

def make_request(uri, request_options):
	'''Generator that returns results to wrapper functions for different
	sections of the API.

	Args:
		uri (str): The uri to send the request to.
		request_options (dict): API options to be specified.

	Yields:
		dict: Response the the API request.
	'''	
	options = copy.deepcopy(request_options)
	r = json.loads(requests.get('%s%s' % (_URL, uri), data=options).text)
	yield r

	options['limit'] = r[u'data'][u'items_per_page']
	while r[u'data'][u'current_item_count'] > 0:
		options['offset'] = r[u'data'][u'index'] + options['limit']
		r = json.loads(requests.get('%s%s' % (_URL, uri), data=options).text)
		yield r

def get_video(options, sample_id, blocksize=1024):
	'''Retrieves the video related to a sample submission.

	Args:
		options (dict): Options for the API request.
		sample_id (str): Sample ID for the video requested.
		blocksize (int): Requested chunk size for yielded blocks.

	Yields:
		bytes: Requested block size of the file returned by the API.
	'''
	r = requests.get('%s/samples/%s/video.webm' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_analysis(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/analysis.json' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_processes(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/processes.json' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_pcap(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/network.pcap' % (_URL, sample_id), 
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_registry(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/registry.json' % (_URL, sample_id), 
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_warnings(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/warnings.json' % (_URL, sample_id), 
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_summary(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/summary' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_threats(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/threat' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_report(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/report.html' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def get_sample(options, sample_id, blocksize=1024):
	r = requests.get('%s/samples/%s/sample.zip' % (_URL, sample_id),
		data=options)
	for block in r.iter_content(blocksize):
		yield block

def search_samples(options):
	'''Generator that searches the Threatgrid API for samples.
	Args:
		options (dict): The options for API parameters.

	Yields:
		dict: The response from the API.
	'''
	for request in make_request('/samples/search', options):
		yield request

def samples(options):
	
	for request in make_request('/samples', options):
		yield request

def ips(options):
	
	for request in make_request('/iocs/feeds/ips', options):
		yield request

def domains(options):

	for request in make_request('/iocs/feeds/domains', options):
		yield request

def urls(options):

	for request in make_request('/iocs/feeds/urls', options):
		yield request

def artifacts(options):
	
	for request in make_request('/iocs/feeds/urls', options):
		yield request

def paths(options):

	for request in make_request('/iocs/feeds/paths', options):
		yield request

def network_streams(options):

	for request in make_request('/iocs/feeds/network_streams', options):
		yield request

def registry_keys(options):

	for request in make_request('/iocs/feeds/registry_keys', options):
		yield request
