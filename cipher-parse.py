#!/usr/bin/env python
import requests
import argparse
import sys
import json
import subprocess
import os


BASE_URL = "https://crt.sh/?q={}&output=json"

   
parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -d google.com")
parser._optionals.title = "OPTIONS"
parser.add_argument('-d', '--domain', type=str, help='Specify Target Domain to get subdomains from crt.sh', required=True)
query =  parser.parse_args()
foo = query.domain
bar = 'common_name'

# get json output from crt.sh and output to file named output.json
r = requests.get(BASE_URL.format(str(foo)), timeout=25)
snap = r.json()
most = json.dumps(snap)
with open('output.json', 'w') as file:
    file.write(most)

# read output.json, and search for value of bar

f = open('output.json',)
data = json.load(f)
query_search = []
for i in data:
    if bar in i:
        query_search.append(i[bar])
    else:
        print("No common name found for ", foo)
f.close()

print(query_search)

# make hostfile to runn sslyze aginst
hostlist = open('hostlist.txt', 'w')
for element in query_search:
    hostlist.write(element + '\n')
hostlist.close()

#run SSLyze
subprocess.run(['sslyze', '--regular', '--json_out=scan-results.json', '--targets_in=hostlist.txt' ])

#parse results for compliance

def scan_results():
    BAD_CIPHERS = ['PSK_AES128_CBC_SHA', 'PSK_AES256_CBC_SHA' , 'PSK_AES128_GCM_SHA256', 'PSK_AES256_GCM_SHA384', 'ECDHE_PSK_AES128', 'ECDHE_PSK_AES256', 'RC4', 'NULL', 'IDEA', 'DES', '3DES', 'EDH', 'ADH', 'DH', 'DHE', 'CAMELLIA', 'SEED', 'ECDH', 'AECDH', 'EXP1024']
    try:
        os.makedirs("./out")
    except FileExistsError:
    # directory already exists
        pass

    with open('scan-results.json', 'r') as r:
        data = json.load(r)
    ssl2 = json.dumps(data['server_scan_results'][0]['scan_commands_results']['ssl_2_0_cipher_suites']['accepted_cipher_suites'])
    ssl3 = json.dumps(data['server_scan_results'][0]['scan_commands_results']['ssl_3_0_cipher_suites']['accepted_cipher_suites'])
    tls10 = json.dumps(data['server_scan_results'][0]['scan_commands_results']['tls_1_0_cipher_suites']['accepted_cipher_suites'])
    tls11 = json.dumps(data['server_scan_results'][0]['scan_commands_results']['tls_1_1_cipher_suites']['accepted_cipher_suites'])
    tls12 = json.dumps(data['server_scan_results'][0]['scan_commands_results']['tls_1_2_cipher_suites']['accepted_cipher_suites'])
    tls13 = json.dumps(data['server_scan_results'][0]['scan_commands_results']['tls_1_2_cipher_suites']['accepted_cipher_suites'])
    print('----------------BAD CIPHER LIST ------\n')
    if ssl2 != '[]':
        print('Illegal usage of SSLv2')
    if ssl3 != '[]':
        print('Illegal usage of SSLv3')
    if tls10 != '[]':
        print('Illegal usage of TLSv1.0')
    with open('./out/tls1-1.json', 'w') as file:
        file.write(tls11)
    with open('./out/tls1-2.json', 'w') as file:
        file.write(tls12)
    with open('./out/tls1-3.json', 'w') as file:
        file.write(tls13)
    for item in BAD_CIPHERS:
        if item in tls11:
            print(item + ' Found in TLSv1.1')
        elif item in tls12:
            print(item + ' Found in TLSv1.2')
        elif item in tls13:
            print(item + ' Found in TLSv1.3')
scan_results()
