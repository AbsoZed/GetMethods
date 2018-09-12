#!/usr/bin/python

import sys
import getopt
import httplib
import csv


def main(argv):
	inputfile = ''
	outputfile = ''
	notvulnsites = []
	vulnsites = []

	
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
			else:
				print site + ' did not return a header. Assuming it is clean.'
				notvulnsites.append(site)
				
		except NameError:
			print 'Holy Shit, you broke it!'
	
	print '\nCLEAN SITES:' + str(notvulnsites)
	print '\nVULNERABLE SITES:' + str(vulnsites)
	
	#To be implemented. Trying to make Python play nice with CSV makes me sad.
	
	#with open (outputfile, 'w') as outfile:
	#			writer = csv.writer(outfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
	#			fields = ['Vulnerable Sites', 'False Positives']
	#			writer.writerows([fields])
	

if __name__ == "__main__":
	main(sys.argv[1:])
