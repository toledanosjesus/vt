#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Jesus Toledano
#
import requests, os, json

HASH_LIST = "hashes.txt"
CONVERTED_HASH_LIST = "converted_hashes.csv"
API_KEY = "PASTE_YOUR_API_KEY_HERE"

def check_requirements():
    global HASH_LIST
    global CONVERTED_HASH_LIST

    if os.path.isfile(HASH_LIST) == True:
        if os.path.isfile(CONVERTED_HASH_LIST) == False:
            with open(CONVERTED_HASH_LIST,"w") as converted_hashes:
                converted_hashes.write("MD5"+";"+
                                        "SHA1"+";"+
                                        "SHA256"+";"+
                                        "Positives"+"\n")
            converted_hashes.close()
        return True
    else:
        return False

def hash_converter(HASH_LIST,CONVERTED_HASH_LIST):
    global API_KEY

    HEADER = {'x-apikey': API_KEY}
    URL = "https://www.virustotal.com/api/v3/files/"


    with open(HASH_LIST,"r") as hashes:
        for hash in hashes.readlines():
            url = URL + hash
            get_report = requests.get(url, headers=HEADER)
            data = get_report.json()
            md5 = data["data"]["attributes"]["md5"]
            SHA1 = data["data"]["attributes"]["sha1"]
            SHA256 = data["data"]["attributes"]["sha256"]
            positives = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

            with open(CONVERTED_HASH_LIST,"a") as converted_hashes:
                converted_hashes.write(str(md5)+";"+
                                        str(SHA1)+";"+
                                        str(SHA256)+";"+
                                        str(positives)+";\n")
            converted_hashes.close()

if __name__ == '__main__':
    reqs = check_requirements()
    if reqs == False:
        print("Sorry, missing the file "+HASH_LIST+".")
    else:
        hash_converter(HASH_LIST,CONVERTED_HASH_LIST)
