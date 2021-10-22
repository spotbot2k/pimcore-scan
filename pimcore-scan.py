#!/usr/bin/python
import requests, argparse, re, sys
from concurrent.futures import thread, ThreadPoolExecutor
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
parser.add_argument('-R', '--redirects', help='Detect host redirection', default=False, action='store_true')
parser.add_argument('-s', '--status', help='Check for SSL redirect', default=False, action='store_true')
parser.add_argument('-S', '--sitemaps', help='Find sitemap files', default=False, action='store_true')
parser.add_argument('-t', '--timeout', help='Connection TTL', default=3, type=int)
parser.add_argument('-T', '--threads', help='Threads to be executed in parallel', default=1, type=int)
parser.add_argument('-u', '--user-agent', help='Use custom user agent string', default=False)
parser.add_argument('-v', '--version', help='Detect instaleld pimcore version', default=False, action='store_true')
parser.add_argument('-V', '--verbose', help='Show detailed error messages', default=False, action='store_true')
args = parser.parse_args()

requests.packages.urllib3.disable_warnings()

def runHost(host):
    s = scanner(host, args)
    return s.get_csv_string()

if args.input_file:
    with open(args.host,) as file:
        host_queue = []

        for line in file:
            stripped_line = line.strip()
            regex = re.compile('(?P<schema>http[s]{0,1}:\/\/){0,1}(?P<host>[0-9a-z\.-]+)(?P<path>\/.*){0,1}')
            try:
                host_queue.append(regex.search(stripped_line).group('host'))
            except Exception as e:
                if (args.verbose):
                    print("%s: %s" % (args.host, str(e)))
                else:
                    print("%s in not a valid host" % stripped_line)

        if args.threads > 1:
            args.csv = True
            print("Host;Ip;SSL-Redirect;Version")

            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                futures = []
                for host in host_queue:
                    try:
                        futures.append(executor.submit(runHost, host=host))
                    except:
                        executor._threads.clear()
                        thread._threads_queues.clear()
        else:
            if (args.csv):
                print("Host;Redirected From;Ip;SSL-Redirect;Version")
            for host in host_queue:
                try:
                    s = scanner(host, args)
                except KeyboardInterrupt:
                    sys.exit()
                except Exception as e:
                    if (args.verbose):
                        print("%s: %s" % (args.host, str(e)))
else:
    regex = re.compile('(?P<schema>http[s]{0,1}:\/\/){0,1}(?P<host>[0-9a-z\.-]+)(?P<path>\/.*){0,1}')
    try:
        host = regex.search(args.host).group('host')
        if (args.csv):
            print("Host;Redirected From;Ip;SSL-Redirect;Version")
        s = scanner(host, args)
    except Exception as e:
        if (args.verbose):
            print("%s: %s" % (args.host, str(e)))