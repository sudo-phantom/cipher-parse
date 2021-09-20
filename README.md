# cipher-parse
use sslyze against a list of hosts found on crt.sh

python -m pip install -r requirements.txt

usage: cipher-parse.py [-h] -d DOMAIN

OPTIONS:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Specify Target Domain to get subdomains from crt.sh

Example: python3 .\cipher-parse.py -d google.com
