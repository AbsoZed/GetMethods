#!/usr/bin/env python

import ssl
import sys
import getopt
import httplib
import csv
import pandas as pd

"""
from termcolor import colored, cprint

Requires VT-100 support which I do not currently have on my work machine.
Can be uncommented to allow use of cprint('word','color')
"""



def main(argv):
	inputfile = ''
	outputfile = ''
	notvulnsites = []
	vulnsites = []
	knownhttpcodes = [301, 500, 501, 405]
	
	try:
		opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
	except getopt.GetoptError:
		print('\nCould not interpret argument. What are you doing?')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print('\n-i <input file> -h <display this message>')
			sys.exit()
		elif opt in ('-i', '--ifile'):
			inputfile = arg
		elif opt in ('-o', '--ofile'):
			outputfile = arg

	sites = open(inputfile, "r")

	for line in sites.readlines():
		
		try:
			site = line.rstrip()
			cxn = httplib.HTTPConnection(site)
			cxn.request('OPTIONS', '/')
			response = cxn.getresponse()
			cxn.close()
		except:
			print 'FQDN could not be resolved. Moving on.'
		
		
		if response.status == 302:
			print '\nGot Status: ' + str(response.status), response.reason + ': Trying HTTPS before giving up.'
			cxn = httplib.HTTPSConnection(site, timeout=5, context=ssl._create_unverified_context())
			cxn.request('OPTIONS', '/')
			response = cxn.getresponse()
			result = response.getheader('allow')
			cxn.close()
		else:
			print '\nGot Status: ' + str(response.status), response.reason + ': '
			result = response.getheader('allow')
			cxn.close()
		
		try:
			if result is not None:
				print 'Allowed methods are ' + result
				if 'OPTIONS' not in result:
					print site + ' is not vulnerable.'
					notvulnsites.append(site)
				else:
					print '\n' + site + ' is VULNERABLE.'
					vulnsites.append(site)
			elif response.status in knownhttpcodes:
				print site + ' is not vulnerable, returned known HTTP Code used for mitigation.'
				notvulnsites.append(site)
			else:
				print site + ' did not return a header. Assuming it is clean.'
				notvulnsites.append(site)
		except NameError:
			print 'Failed to run! Check format of files, internet connection.'
	
	print '\nCLEAN SITES:' + str(notvulnsites)
	print '\nVULNERABLE SITES:' + str(vulnsites)
	
	
	if outputfile is not '':
		try:
			pd.concat([pd.DataFrame({'Vulnerable Sites':vulnsites}),pd.DataFrame({'Possible False Positives':notvulnsites})],axis=1).to_csv(outputfile)
		except:
			print 'Couldn\'t lock file! Check permissions and open files!'
	

if __name__ == "__main__":
	main(sys.argv[1:])
