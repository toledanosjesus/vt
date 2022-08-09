# vt-hash-converter

This script will convert a list of hashes into MD5, SHA1 and SHA256 using VirusTotal service V3.
It will read line by line an input file which is named hashes.txt by default. Then, it will save the output into a CSV file called converted_hashes.csv.

You can change that under the global variable list:

HASH_LIST = "hashes.txt"
CONVERTED_HASH_LIST = "converted_hashes.csv"
API_KEY = "PASTE_YOUR_API_KEY_HERE"

Please, remember to change the API_KEY with your own one, otherwise the script won't work.

Example:

$ cat hashes.txt 

d27328a9242e487e0833d01c76b8e625fe4fd66b2c97aad3648b1df2cacfc4e3

$ python vt-hash-converter.py 

$ cat converted_hashes.csv 

MD5;SHA1;SHA256;Positives
bfa8d5424259f32d7bd9fe1b91674ce4;eef85891d46931dac5341ae2325510172e08d426;d27328a9242e487e0833d01c76b8e625fe4fd66b2c97aad3648b1df2cacfc4e3;2;
