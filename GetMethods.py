#!/usr/bin/env python

import sys
import getopt
import httplib
import csv
import pandas as pd
#from termcolor import colored, cprint

"""
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
		site = line.rstrip()
		cxn = httplib.HTTPConnection(site)
		cxn.request('OPTIONS', '/')
		response = cxn.getresponse()
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
				print site + ' is not vulnerable, returned known HTTP Error Code.'
				notvulnsites.append(site)
			else:
				print site + ' did not return a header. Assuming it is clean.'
				notvulnsites.append(site)
		except NameError:
			print 'Holy shit, you broke it!'
	
	print '\nCLEAN SITES:' + str(notvulnsites)
	print '\nVULNERABLE SITES:' + str(vulnsites)
	
	if outputfile is not '':
		try:
			CSVOut = {'Vulnerable Sites':vulnsites,'False Positives':notvulnsites}
			df = pd.DataFrame.from_dict(CSVOut, orient='index')
			df.to_csv(outputfile)
		except:
			print 'Couldn\'t lock file! Check permissions and open files!'
	

if __name__ == "__main__":
	main(sys.argv[1:])
