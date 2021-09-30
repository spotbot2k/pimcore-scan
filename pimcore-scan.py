#!/usr/bin/python
import requests, argparse, re
from scanner import scanner

parser = argparse.ArgumentParser(description='Simple pimcore status scanner.')
parser.add_argument('host', help='Hostname of the target without the schema (e.g. example.com)')
parser.add_argument('-a', '--all', help='Perform all checks', default=False, action='store_true')
parser.add_argument('-b', '--bundles', help='Detect installed bundles', default=False, action='store_true')
parser.add_argument('-B', '--basic-auth', help='Use basic auth header (username:password)', default=False)
parser.add_argument('-c', '--csv', help='Use csv formated output', default=False, action='store_true')
parser.add_argument('-d', '--domains', help='Detect domains based on sitemaps', default=False, action='store_true')
parser.add_argument('-H', '--headers', help='Scan response headers', default=False, action='store_true')
parser.add_argument('-i', '--input-file', help='Use a list of hosts in a file instead of stdio', default=False, action='store_true')
parser.add_argument('-I', '--ip', help='Detect the ip adress of the server', default=False, action='store_true')
parser.add_argument('-l', '--login', help='Check if login route is visible', default=False, action='store_true')
parser.add_argument('-p', '--ping', help='Ping every entry in the sitemap and print the status', default=False, action='store_true')
parser.add_argument('-r', '--robots', help='Search robots.txt', default=False, action='store_true')
parser.add_argument('-s', '--status', help='Check for SSL redirect', default=False, action='store_true')
parser.add_argument('-S', '--sitemaps', help='Find sitemap files', default=False, action='store_true')
parser.add_argument('-t', '--timeout', help='Connection TTL', default=3, type=int)
parser.add_argument('-u', '--user-agent', help='Use custom user agent string', default=False)
parser.add_argument('-v', '--version', help='Detect instaleld pimcore version', default=False, action='store_true')
parser.add_argument('-V', '--verbose', help='Show detailed error messages', default=False, action='store_true')
args = parser.parse_args()

requests.packages.urllib3.disable_warnings()

if args.input_file:
    with open(args.host,) as file:
        if args.csv:
            print("Host;Ip;SSL-Redirect;Version")
        for line in file:
            stripped_line = line.strip()
            regex = re.compile('(?P<schema>http[s]{0,1}:\/\/){0,1}(?P<host>[0-9a-z\.-]+)(?P<path>\/.*){0,1}')
            try:
                host = regex.search(stripped_line).group('host')
                if not args.csv:
                    print(host)
                s = scanner(host, args)
            except:
                print("%s in not a valid host" % stripped_line)
else:
    regex = re.compile('(?P<schema>http[s]{0,1}:\/\/){0,1}(?P<host>[0-9a-z\.-]+)(?P<path>\/.*){0,1}')
    try:
        host = regex.search(args.host).group('host')
        s = scanner(host, args)
    except Exception as e:
        if (args.verbose):
            print("%s: %s" % (args.host, str(e)))
