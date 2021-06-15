#!/usr/bin/python
import requests, argparse, json, os
import xml.etree.ElementTree as xml

parser = argparse.ArgumentParser(description='Simple pimcore status scanner.')
parser.add_argument('host', help='Hostname of the target without the schema (e.g. example.com)')
parser.add_argument('-a', '--all', help='Perform all checks', default=False, action='store_true')
parser.add_argument('-b', '--bundles', help='Detect installed bundles', default=False, action='store_true')
parser.add_argument('-H', '--headers', help='Scan response headers', default=False, action='store_true')
parser.add_argument('-l', '--login', help='Check if login route is visible', default=False, action='store_true')
parser.add_argument('-p', '--ping', help='Ping every entry in the sitemap and print the status', default=False, action='store_true')
parser.add_argument('-r', '--robots', help='Search robots.txt', default=False, action='store_true')
parser.add_argument('-s', '--status', help='Check for SSL redirect', default=False, action='store_true')
parser.add_argument('-S', '--sitemap', help='Fetch domains from the sitemap', default=False, action='store_true')
parser.add_argument('-v', '--version', help='Detect instaleld pimcore version', default=False, action='store_true')
args = parser.parse_args()

# Valiables

ns = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
host = 'http://' + args.host
response = requests.get(host, allow_redirects=True)
pwd = os.path.dirname(os.path.realpath(__file__))

# Save the resulting URL to avoid all the redirects in future requests
if (response.request.path_url != '/'):
    host = response.url[:len(response.url) - len(response.request.path_url)]
else:
    host = response.url

if (host[-1] != '/'):
    host += '/'

def host_has_file(host, file):
    response = requests.get(host + file, allow_redirects=True)
    if (response.status_code == 200 and file in response.url):
        return True
    return False

def get_url_status_code(url):
    response = requests.get(url, allow_redirects=True)
    return response.status_code

def split_robots_line(line):
    content = line.split(': ')
    if (len(content) > 1):
        return content[1]
    else:
        return False

def analyse_robots_line(line):
    if ('Disallow' in line):
        str = split_robots_line(line)
        if (str != False and str != '/'):
            print('Found a disabled path in robotx.txt: %s' % str)
    if ('Sitemap:' in line and line.index('Sitemap') == 0):
        str = split_robots_line(line)
        if (str != False):
            print('Found a sitemap in robots.txt: %s' % str)

def fetch_domain_from_sitemap(sitemapUrl):
    response = requests.get(sitemapUrl, allow_redirects=True)
    if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
        sitemap = xml.fromstring(response.text)
        return sitemap.find('sitemap:url', ns).find('sitemap:loc', ns).text

def detect_version():
    if (host_has_file(host, 'pimcore/static/swf/expressInstall.swf')):
        return '<= 4.6.5'

    if (host_has_file(host, 'bundles/pimcoreadmin/js/lib/jquery-3.4.1.min.js')):
        return '6.0.0 <= x <= 6.2.3'

    if (host_has_file(host, 'bundles/pimcoreadmin/js/lib/jquery-3.3.1.min.js')):
        return '5.4.0 <= x <= 5.8.9'

    if (host_has_file(host, 'pimcore/static6/js/lib/jquery-3.3.1.min.js')):
        return '5.2.0 <= x <= 5.3.1'

    if (not host_has_file(host, 'bundles/pimcoreadmin/js/lib/ext/ext-all.js') and host_has_file(host, 'bundles/pimcorecore/js/targeting.js')):
        return '>= 10'

    if (host_has_file(host, 'bundles/pimcoreadmin/js/lib/ckeditor/plugins/clipboard/dialogs/paste.js')):
        return '6.5.0 <= x <= 10'

if args.status or args.all:
    print('\n# Server status')
    if ('https' not in response.url or response.url.index('https') != 0):
        print('WARNING: No SSL Redirection applied!')
    else:
        print('SSL redirection is in place')
    print('Status Code: %d (%s)' % (response.status_code, response.reason))
    print('Server: %s' % response.headers.get('Server'))

if args.headers or args.all:
    print('\n# Debug')
    for key,val in response.headers.items():
        if (key == 'X-Powered-By'):
            print('X-Powerde-By: %s' % val)
        if (key == 'X-Debug-Token-Link'):
            print('Debug exposed: %s' % val)

if args.login or args.all:
    print('\n# Login')
    response = requests.get(host + 'admin', allow_redirects=True)
    if ('admin/login' in response.url):
        print('Login: /admin is detected and visible')

if args.version or args.all:
    print('\n# Pimcore Version')
    version = detect_version()
    if version:
        print('Detected version: %s' % version)

if args.robots or args.all:
    print('\n# Robots.txt')
    response = requests.get(host + 'robots.txt', allow_redirects=False)
    if ('text/plain' in response.headers.get('Content-type')):
        for line in response.iter_lines():
            analyse_robots_line(line.decode("utf-8"))

if args.sitemap or args.all:
    print('\n# Sitemaps')
    response = requests.get(host + 'sitemap.xml', allow_redirects=True)
    if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
        sitemap = xml.fromstring(response.text)
        sites = []

        for child in sitemap.findall('sitemap:sitemap', ns):
            sitemapFile = child.find('sitemap:loc', ns).text
            print('Sitemap fund: %s' % sitemapFile)
            if ('site_' in sitemapFile):
                sites.append(sitemapFile)
        for sitemapFile in sites:
            domain = fetch_domain_from_sitemap(sitemapFile)
            if isinstance(domain, str):
                print('Found domain in sitemap: %s' % domain)
    else:
        print('No sitemap found')

if args.ping:
    response = requests.get(host + 'sitemap.xml', allow_redirects=True)
    if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
        sitemap = xml.fromstring(response.text)
        sites = []

        for child in sitemap.findall('sitemap:sitemap', ns):
            sitemapFile = child.find('sitemap:loc', ns).text
            subRequest = requests.get(sitemapFile, allow_redirects=True)
            if (subRequest.status_code == 200 and subRequest.headers.get('Content-Type') == 'application/xml'):
                sitemap = xml.fromstring(subRequest.text)
                for node in sitemap.findall('sitemap:url', ns):
                    url = node.find('sitemap:loc', ns).text
                    statusCode = get_url_status_code(url)
                    if (statusCode != 200):
                        print("%d;%s" % (statusCode, url))

if args.bundles or args.all:
    print('\n# Installed bundles')
    for file in os.listdir(pwd + '/bundles'):
        if file.endswith(".json"):
            f = open(pwd + '/bundles/' + file,)
            plugin = json.loads(f.read())
            if (host_has_file(host, plugin['path'])):
                print('Bundle Detected: %s by %s' % (plugin['name'], plugin['author']))
            f.close()