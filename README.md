# Pimcore Scan

Simple scaner for [Pimcore](https://github.com/pimcore/pimcore). It is not ment to be used as a voulnerability scaner but rather for service and maintenance.

At this point this is still in early development state.

## Installation

``` bash
python -m pip install -r requirements.txt
```

## Usage

To perform checks

``` bash
python pimcore-scan -a example.com
```

To check the sitemap (will not do it with -a)

``` bash
python pimcore-scan -p example.com
```

To check multiple domains write them in a file (one per line)

``` bash
python pimcore-scan -ia example.com
```

Combine checks as needed

``` bash
python pimcore-scan -vH example.com
```

``` bash
  -h, --help            show this help message and exit
  -a, --all             Perform all checks
  -A, --average-time    Measure average response time
  -b, --bundles         Detect installed bundles
  -B USER:PASSWORD, --basic-auth USER:PASSWORD
                        Use basic auth header (username:password)
  -d, --domains         Detect domains based on sitemaps
  -f, --fast            Use fast version scan (major only)
  -H, --headers         Scan response headers
  -i, --input_file      Use a list of hosts in a file instead of stdio
  -I, --ip              Detect the ip adress of the server
  -l, --login           Check if login route is visible
  -p, --ping            Ping every entry in the sitemap and print the status
  -P, --pause           Pause between connections
  -r, --robots          Search robots.txt
  -R, --redirects       Detect and display domain redirection
  -s, --status          Check for SSL redirect
  -S, --sitemaps        Find sitemap files
  -t, --timeout         Connection TTL
  -u USER_AGENT, --user-agent USER_AGENT
                        Use custom user agent string
  -v, --version         Detect instaleld pimcore version
  -V, --verbose         Show detailed error messages

  --guess-cms           Try to guess CMS used
```

## What does work
 - aproximate version detection of the installation based on frontend dependencies
 - Debug detection
 - Detects hiden folders via robots.txt
 - Detects if /admin route is accessable
 - Detects if SSL redirection is enforced
 - Domain detection based on the sitemap
 - Detect (some) installed bundles
 - Ping sitemap entries and detect problems (e.G. status 404, 500)

## What is planed
 - More precise version detection
 - Mode build-in bundle detections

## Contribute

You are welcome to cuntribute in any way. The easiest thing for the start is to add a json file for a bundle to be scanned. Put your file into the `bundles` folder and make sure the content is a valid JSON with `name`, `path` and `author` in it.

`path` is the relative url to a frontend dependency to be searched for. `bundle.js` or `startup.js` will do. If the dependency is only valid for a certain versionb please make sure to write it in the `name`. The `path` will be apended to the host and pinged, if found the message about this bundle will appear in the log.
