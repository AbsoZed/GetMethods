#/usr/bin/python

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
		print('\n' + 'Could not interpret argument. What are you doing?')
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print('\n' + '-i <input file> -h <display this message>')
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
		print '\n'
		print 'Got Status: ' + str(response.status), response.reason + ' - '
		result = response.getheaders()
		cxn.close()

		if 'GET' not in result:
			print site + ' is not vulnerable.'
			notvulnsites.append(site)
			
		elif 'GET' in result:
			print '\n'
			print line + ' is VULNERABLE.'
			vulnsites.append(site)
	print '\n'
	print 'CLEAN SITES:' + str(notvulnsites)
	print '\n'
	print 'VULNERABLE SITES:' + str(vulnsites)
	
	#To be implemented. Trying to make Python play nice with CSV makes me sad.
	
	#with open (outputfile, 'w') as outfile:
	#			writer = csv.writer(outfile, delimiter=',',quotechar='"', quoting=csv.QUOTE_MINIMAL)
	#			fields = ['Vulnerable Sites', 'False Positives']
	#			writer.writerows([fields])
	

if __name__ == "__main__":
	main(sys.argv[1:])
