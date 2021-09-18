import requests
import argparse
import sys
import json
import subprocess


BASE_URL = "https://crt.sh/?q={}&output=json"

   
parser = argparse.ArgumentParser(epilog='\tExample: \r\npython3 ' + sys.argv[0] + " -d google.com")
parser._optionals.title = "OPTIONS"
parser.add_argument('-d', '--domain', help='Specify Target Domain to get subdomains from crt.sh', required=True)
query =  parser.parse_args()
foo = query.domain
bar = 'common_name'

# get json output from crt.sh and output to file named output.json
r = requests.get(BASE_URL.format(foo), timeout=25)
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


