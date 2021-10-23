import requests, json, os, base64, re
import xml.etree.ElementTree as xml

class scanner:

    SITEMAP_NAMESPACE = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
    PROJECT_ROOT = os.path.dirname(os.path.realpath(__file__))
    CSV_HEADER = "Host;Redirected From;Ip;SSL-Redirect;Version"

    def __init__(self, host, args):
        self.args = args
        self.host = 'http://' + host
        self.headers = {}
        self.ip = ""
        self.ssl = ""
        self.version = ""
        self.redirected = False
        self.originalHost = ""

        if args.user_agent:
            self.headers = {
                'User-Agent': args.user_agent
            }

        if args.basic_auth:
            self.headers["Authorization"] = "Basic " + base64.b64encode(str.encode(args.basic_auth)).decode('ascii')

        response = requests.get(self.host, allow_redirects=True, headers=self.headers, verify=False, timeout=args.timeout)
        self.redirected = not bool(self.compare_hosts(self.host, response.url))
        self.originalHost = self.host

        # Save the resulting URL to avoid all the redirects in future requests
        if response.request.path_url != '/':
            self.host = response.url[:len(response.url) - len(response.request.path_url)]
        else:
            self.host = response.url

        if self.host[-1] != '/':
            self.host += '/'

        if args.status or args.all:
            if ('https' not in response.url or response.url.index('https') != 0):
                print('WARNING: No SSL Redirection applied!')
            else:
                self.ssl = "Yes"
                if not args.csv:
                    print('SSL redirection is in place')
            if not args.csv:
                print('Status Code: %d (%s)' % (response.status_code, response.reason))
                print('Server: %s' % response.headers.get('Server'))

        if args.version or args.all:
            self.version = self.detect_version()
            if (self.version and args.all) and not args.csv:
                print('Detected version: %s' % self.version)
            if self.version and args.version:
                if not args.csv:
                    print(self.version)

        if (args.headers or args.all) and not args.csv:
            for key,val in response.headers.items():
                if (key == 'X-Powered-By'):
                    print('X-Powerde-By: %s' % val)
                if (key == 'X-Debug-Token-Link'):
                    print('Debug exposed: %s' % val)

        if args.ip or args.all:
            try:
                response = requests.get(self.host, stream=True, allow_redirects=True, headers=self.headers, verify=False, timeout=args.timeout)
                self.ip , port = response.raw._connection.sock.getpeername()
                if not args.csv:
                    print("Server IP: %s" % self.ip)
            except:
                pass

        if args.login or args.all:
            response = requests.get(self.host + 'admin', allow_redirects=True, headers=self.headers, verify=False, timeout=args.timeout)
            if ('admin/login' in response.url):
                print('Login: /admin is detected and visible')

        if args.robots or args.all:
            response = requests.get(self.host + 'robots.txt', allow_redirects=False, headers=self.headers, verify=False, timeout=args.timeout)
            if ('text/plain' in response.headers.get('Content-type')):
                for line in response.iter_lines():
                    self.analyse_robots_line(line.decode("utf-8"))

        if (args.domains or args.sitemaps or args.all) and not args.csv:
            response = requests.get(self.host + 'sitemap.xml', allow_redirects=True, headers=self.headers, verify=False, timeout=args.timeout)
            if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
                sitemap = xml.fromstring(response.text)
                sites = []

                for child in sitemap.findall('sitemap:sitemap', self.SITEMAP_NAMESPACE):
                    sitemapFile = child.find('sitemap:loc', self.SITEMAP_NAMESPACE).text
                    if args.sitemaps or args.all:
                        print(sitemapFile)
                    if ('site_' in sitemapFile):
                        sites.append(sitemapFile)
                for sitemapFile in sites:
                    domain = self.fetch_domain_from_sitemap(sitemapFile)
                    if isinstance(domain, str) and (args.domains or args.all):
                        print(domain)
            else:
                print('No sitemap found')

        if args.ping:
            response = requests.get(self.host + 'sitemap.xml', allow_redirects=True, headers=self.headers, verify=False, timeout=args.timeout)
            if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
                sitemap = xml.fromstring(response.text)
                sites = []

                for child in sitemap.findall('sitemap:sitemap', self.SITEMAP_NAMESPACE):
                    sitemapFile = child.find('sitemap:loc', self.SITEMAP_NAMESPACE).text
                    subRequest = requests.get(sitemapFile, allow_redirects=True, headers=self.headers, verify=False, timeout=args.timeout)
                    if (subRequest.status_code == 200 and subRequest.headers.get('Content-Type') == 'application/xml'):
                        sitemap = xml.fromstring(subRequest.text)
                        for node in sitemap.findall('sitemap:url', self.SITEMAP_NAMESPACE):
                            url = node.find('sitemap:loc', self.SITEMAP_NAMESPACE).text
                            statusCode = self.get_url_status_code(url)
                            if (statusCode != 200):
                                print("%d;%s" % (statusCode, url))

        if  self.redirected and args.redirects or args.all:
            if not args.csv:
                print("Redirected to %s" % self.host)

        if (args.bundles or args.all) and not args.csv:
            for file in os.listdir(self.PROJECT_ROOT + '/bundles'):
                if file.endswith(".json"):
                    f = open(self.PROJECT_ROOT + '/bundles/' + file,)
                    plugin = json.loads(f.read())
                    if (self.host_has_file(self.host, plugin['path'])):
                        print('Bundle Detected: %s by %s, %s' % (plugin['name'], plugin['author'], plugin['url']))
                    f.close()

        if args.csv:
            print(self.get_csv_string())

    def host_has_file(self, host, file):
        try:
            response = requests.get(host + file, allow_redirects=True, headers=self.headers, verify=False, timeout=self.args.timeout)
            if (response.status_code == 200 and file in response.url and response.headers['Content-Type'].find("html") < 0):
                return True
            else:
                return False
        except:
            return False

    def compare_hosts(self, request_url, response_url):
        regex = re.compile('(?P<schema>http[s]{0,1}:\/\/){0,1}(?P<host>[0-9a-z\.-]+)(?P<path>\/.*){0,1}')
        request_host = regex.search(request_url).group('host')
        server_host = regex.search(response_url).group('host')

        return bool(request_host == server_host)

    def get_url_status_code(self, url):
        response = requests.get(url, allow_redirects=True, headers=self.headers, verify=False, timeout=self.args.timeout)
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
        response = requests.get(sitemapUrl, allow_redirects=True, headers=self.headers, verify=False, timeout=self.args.timeout)
        if (response.status_code == 200 and response.headers.get('Content-Type') == 'application/xml'):
            sitemap = xml.fromstring(response.text)
            return sitemap.find('sitemap:url', self.SITEMAP_NAMESPACE).find('sitemap:loc', self.SITEMAP_NAMESPACE).text

    def get_csv_string(self):
        return ";".join([self.host, str(self.originalHost), str(self.ip), str(self.ssl), str(self.version)])

    def detect_version(self):
        if (self.host_has_file(self.host, 'bundles/pimcoreadmin/img/login/pcx.svg')):
            if (self.host_has_file(self.host, 'bundles/pimcoreadmin/img/flat-color-icons/static_page.svg')):
                return '10.1'
            return '10.0'

        if (self.host_has_file(self.host, 'bundles/pimcoreadmin/img/login/pimconaut-world.svg')):
            if (not self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/object/bulk-base.js')):
                return '6.0'
            if (not self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/ckeditor/vendor/promise.js')):
                return '6.1'
            if (not self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/asset/gridexport/csv.js')):
                return '6.2'
            if (not self.host_has_file(self.host, 'bundles/pimcoreadmin/img/flat-color-icons/email-forward.svg')):
                return '6.3'
            if (not self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/ckeditor/plugins/clipboard/dialogs/paste.js')):
                return '6.4'
            if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/document/editable.js')):
                if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/document/editables/area_abstract.js')):
                    return '6.9'
                return '6.8'
            if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/asset/metadata/editor.js')):
                return '6.7'
            if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/asset/metadata/data/asset.js')):
                return '6.6'
            return '6.5 <= x <= 6.6'

        if (self.host_has_file(self.host, 'pimcore/static6/img/logo.svg') or self.host_has_file(self.host, 'pimcore/static6/img/logo-white.svg')):
            if (self.host_has_file(self.host, 'pimcore/static6/img/flat-color-icons/book.svg')):
                if (self.host_has_file(self.host, 'pimcore/static6/img/flat-color-icons/warning.svg')):
                    if (self.host_has_file(self.host, 'pimcore/static6/js/pimcore/document/newsletters/addressSourceAdapters/csvList.js')):
                        if (self.host_has_file(self.host, 'pimcore/static6/js/pimcore/document/newsletters/addressSourceAdapters/report.js')):
                            if (self.host_has_file(self.host, 'pimcore/static6/js/pimcore/settings/user/websiteTranslationSettings.js')):
                                if (self.host_has_file(self.host, 'pimcore/static6/js/pimcore/object/helpers/gridCellEditor.js')):
                                    return '4.6'
                                return '4.5'
                            return '4.4'
                        return '4.3'
                    return '4.2'
                return '4.1'
            return '4.0'

        if (self.host_has_file(self.host, 'pimcore/static6/img/logo-claim-gray.svg') or self.host_has_file(self.host, 'pimcore/static6/img/logo.svg')):
            if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/jquery-3.3.1.min.js')):
                if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/element/workflows.js')):
                    if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/pimcore/object/gridcolumn/operator/Iterator.js')):
                        if (self.host_has_file(self.host, 'bundles/pimcoreadmin/js/lib/ckeditor/lang/es-mx.js')):
                            return '5.8'
                        else:
                            return '5.7'
                    return '5.6'
                return '5.4'
            if (self.host_has_file(self.host, 'pimcore/static6/js/lib/jquery-3.3.1.min.js')):
                return '5.2 <= x <= 5.3'
            return '5.0'

        if (self.host_has_file(self.host, 'pimcore/static/img/icon/web-browser_small.png')):
            if (self.host_has_file(self.host, 'pimcore/static6/swf/expressInstall.swf')):
                return '3.1'
            return '3.0'

        if (self.host_has_file(self.host, 'pimcore/static/img/login/logo.png')):
            return '2'