# Pimcore Scan

Simple scaner for [Pimcore](https://github.com/pimcore/pimcore). It is not ment to be used as a voulnerability scaner but rather for service and maintenance.

At this point is still in early development state.

## Installation

``` bash
python -m pip install -r requirements.txt
```

## Usage

``` bash
usage: ./pimcore-scan.py example.com -a

positional arguments:
  host           Hostname of the target without the schema (**example.com**)

optional arguments:
  -h, --help     show this help message and exit
  -a, --all      Perform all checks
  -b, --bundles  Detect installed bundles
  -H, --headers  Scan response headers
  -l, --login    Check if login route is visible
  -p, --ping     Ping every entry in the sitemap and print the status
  -r, --robots   Search robots.txt
  -s, --status   Check for SSL redirect
  -S, --sitemap  Fetch domains from the sitemap
  -v, --version  Detect instaleld pimcore version
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
