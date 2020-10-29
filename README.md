# vt-hash-converter

This script will convert a list of hashes into MD5, SHA1 and SHA256.
It will read line by line an input file which is named hashes.txt by default. Then, it will save the output into a CSV file called converted_hashes.csv.

You can change that under the global variables list:

HASH_LIST = "hashes.txt"
CONVERTED_HASH_LIST = "converted_hashes.csv"
API_KEY = "PASTE_YOUR_API_KEY_HERE"

Please, remember to change the API_KEY with your own one, otherwise the script won't work.
