# GetMethods
A simple Python script to check for OPTIONS verb on servers. Can be edited for other options easily.

Accepts a list of websites in .txt format, one website per line. Please note that this is written against Python 2.7 - and has not
been tested on 3.X.X

Created in response to Rapid7's insistence the presence of the HTTP-OPTIONS method constitutes a vulnerability. (Right.)

Usage: ./GetMethods.py -i [Input-File] -o [Output File in CSV]

To be added: Single host support
