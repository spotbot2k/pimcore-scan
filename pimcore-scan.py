#!/usr/bin/python
import requests, argparse, json, os, re
import xml.etree.ElementTree as xml

parser = argparse.ArgumentParser(description='Simple pimcore status scanner.')
parser.add_argument('host', help='Hostname of the target without the schema (e.g. example.com)')
parser.add_argument('-a', '--all', help='Perform all checks', default=False, action='store_true')
parser.add_argument('-b', '--bundles', help='Detect installed bundles', default=False, action='store_true')
parser.add_argument('-H', '--headers', help='Scan response headers', default=False, action='store_true')
parser.add_argument('-i', '--input_file', help='Use a list of hosts in a file instead of stdio', default=False, action='store_true')
parser.add_argument('-l', '--login', help='Check if login route is visible', default=False, action='store_true')
parser.add_argument('-p', '--ping', help='Ping every entry in the sitemap and print the status', default=False, action='store_true')
parser.add_argument('-r', '--robots', help='Search robots.txt', default=False, action='store_true')
parser.add_argument('-s', '--status', help='Check for SSL redirect', default=False, action='store_true')
parser.add_argument('-S', '--sitemap', help='Fetch domains from the sitemap', default=False, action='store_true')
parser.add_argument('-v', '--version', help='Detect instaleld pimcore version', default=False, action='store_true')
args = parser.parse_args()

SITEMAP_NAMESPACE = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))

class Scanner:

    def __init__(self, host, args):
        self.host = 'http://' + host

        response = requests.get(self.host, allow_redirects=True)
        # Save the resulting URL to avoid all the redirects in future requests
        if (response.request.path_url != '/'):
            self.host = response.url[:len(response.url) - len(response.request.path_url)]
        else:
            self.host= response.url

        if (self.host[-1] != '/'):
            self.host += '/'

        if args.status or args.all:
            if ('https' not in response.url or response.url.index('https') != 0):
                print('WARNING: No SSL Redirection applied!')
            else:
                print('SSL redirection is in place')
            print('Status Code: %d (%s)' % (response.status_code, response.reason))
            print('Server: %s' % response.headers.get('Server'))

        if args.version or args.all:
            version = self.detect_version()
            if version:
                print('Detected version: %s' % version)

        if args.headers or args.all:
            for key,val in response.headers.items():
                if (key == 'X-Powered-By'):
                    print('X-Powerde-By: %s' % val)
                if (key == 'X-Debug-Token-Link'):
                    print('Debug exposed: %s' % val)

        if args.login or args.all:
            response = requests.get(self.host + 'admin', allow_redirects=True)
            if ('admin/login' in response.url):
                print('Login: /admin is detected and visible')

        if args.robots or args.all:
            response = requests.get(self.host + 'robots.txt', allow_redirects=False)
            if ('text/plain' in response.headers.get('Content-type')):
                for line in response.iter_lines():
                    self.analyse_robots_line(line.decode("utf-8"))

        if args.sitemap or args.all:
            response = requests.get(self.host + 'sitemap.xml', allow_redirects=True)
            if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
                sitemap = xml.fromstring(response.text)
                sites = []

                for child in sitemap.findall('sitemap:sitemap',SITEMAP_NAMESPACE):
                    sitemapFile = child.find('sitemap:loc',SITEMAP_NAMESPACE).text
                    print('Sitemap fund: %s' % sitemapFile)
                    if ('site_' in sitemapFile):
                        sites.append(sitemapFile)
                for sitemapFile in sites:
                    domain = self.fetch_domain_from_sitemap(sitemapFile)
                    if isinstance(domain, str):
                        print('Found domain in sitemap: %s' % domain)
            else:
                print('No sitemap found')

        if args.ping:
            response = requests.get(self.host + 'sitemap.xml', allow_redirects=True)
            if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
                sitemap = xml.fromstring(response.text)
                sites = []

                for child in sitemap.findall('sitemap:sitemap',SITEMAP_NAMESPACE):
                    sitemapFile = child.find('sitemap:loc',SITEMAP_NAMESPACE).text
                    subRequest = requests.get(sitemapFile, allow_redirects=True)
                    if (subRequest.status_code == 200 and subRequest.headers.get('Content-Type') == 'application/xml'):
                        sitemap = xml.fromstring(subRequest.text)
                        for node in sitemap.findall('sitemap:url',SITEMAP_NAMESPACE):
                            url = node.find('sitemap:loc',SITEMAP_NAMESPACE).text
                            statusCode = self.get_url_status_code(url)
                            if (statusCode != 200):
                                print("%d;%s" % (statusCode, url))

        if args.bundles or args.all:
            for file in os.listdir(PROJECT_ROOT + '/bundles'):
                if file.endswith(".json"):
                    f = open(PROJECT_ROOT + '/bundles/' + file,)
                    plugin = json.loads(f.read())
                    if (self.host_has_file(self.host, plugin['path'])):
                        print('Bundle Detected: %s by %s' % (plugin['name'], plugin['author']))
                    f.close()

    def host_has_file(self, host, file):
        try:
            response = requests.get(host + file, allow_redirects=True)
            if (response.status_code == 200 and file in response.url):
                return True
            else:
                return False
        except:
            return False

    def get_url_status_code(self, url):
        response = requests.get(url, allow_redirects=True)
        return response.status_code

    def split_robots_line(self, line):
        content = line.split(': ')
        if (len(content) > 1):
            return content[1]
        else:
            return False

    def analyse_robots_line(self, line):
        if ('Disallow' in line):
            str = self.split_robots_line(line)
            if (str != False and str != '/'):
                print('Found a disabled path in robotx.txt: %s' % str)
        if ('Sitemap:' in line and line.index('Sitemap') == 0):
            str = self.split_robots_line(line)
            if (str != False):
                print('Found a sitemap in robots.txt: %s' % str)

    def fetch_domain_from_sitemap(self, sitemapUrl):
        response = requests.get(sitemapUrl, allow_redirects=True)
        if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
            sitemap = xml.fromstring(response.text)
            return sitemap.find('sitemap:url',SITEMAP_NAMESPACE).find('sitemap:loc',SITEMAP_NAMESPACE).text

    def detect_version(self):
        if (self.host_has_file(self.host, 'pimcore/static6/js/lib/pdf.js/web/viewer.js')):
            return '<= 4.1.3'

        if (self.host_has_file(self.host, 'pimcore/static/swf/expressInstall.swf')):
            return '<= 4.6.5'

        if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/jquery-3.4.1.min.js')):
            return '6.0.0 <= x <= 6.2.3'

        if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/jquery-3.3.1.min.js')):
            return '5.4.0 <= x <= 5.8.9'

        if (self.host_has_file(self.host, 'pimcore/static6/js/lib/jquery-3.3.1.min.js')):
            return '5.2.0 <= x <= 5.3.1'

        if (not self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/ext/ext-all.js') and self.host_has_file(self.host, 'bundles/pimcorecore/js/targeting.js')):
            return '>= 10'

        if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/ckeditor/plugins/clipboard/dialogs/paste.js')):
            if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/document/editable.js')):
                return '6.8.0 <= x <= 10'
            else:
                return '6.5.0 <= x <= 6.7.3'

if args.input_file:
    with open(args.host,) as file:
        for line in file:
            stripped_line = line.strip()
            regex = re.compile('(?P<schema>http[s]{0,1}:\/\/){0,1}(?P<host>[1-9a-z\.-]+)(?P<path>\/.*){0,1}')
            try:
                host = regex.search(stripped_line).group('host')
                print(host)
                s = Scanner(host, args)
            except:
                print("%s in not a valid host" % stripped_line)
else:
    s = Scanner(args.host, args)