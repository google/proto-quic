# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import HTMLParser
import json
import logging
import urllib2
import urlparse


class _HRefParser(HTMLParser.HTMLParser):

  def __init__(self):
    HTMLParser.HTMLParser.__init__(self)
    self.hrefs = []

  def handle_starttag(self, tag, attrs):
    if tag == "a":
      for name, value in attrs:
        if name == "href":
          self.hrefs.append(value)


def _AbsoluteUrlHasSaneScheme(absolute_url):
  if len(absolute_url) < 4:
    return False
  return absolute_url[0:4] == "http"


def GenerateSafeUrls():
  """Prints a list of safe urls.

  Generates a safe list of urls from a seed list. Each href in the HTML
  fetched from the url from the seed list is placed into the safe list. The
  safe list contains unsanitized urls.
  """
  # A list of websites whose hrefs are unlikely to link to sites that contain
  # malware.
  seed_urls = [
      "http://www.cnn.com",
      "https://www.youtube.com",
      "https://www.facebook.com",
      "https://www.twitter.com",
      "https://www.yahoo.com",
      "https://www.amazon.com",
      "https://www.wikipedia.com",
      "https://www.bing.com",
      "https://www.dailymotion.com",
      "https://www.stackoverflow.com",
      "https://www.google.com/#q=dumpling",
      "http://www.baidu.com/s?wd=rice",
      "http://www.baidu.com/s?wd=cow",
      "https://www.google.com/#q=fox",
      "http://www.yahoo.co.jp/",
      "http://www.yandex.ru/",
      "https://www.imdb.com/",
      "http://www.huffingtonpost.com/",
      "https://www.deviantart.com/",
      "http://www.wsj.com/",
  ]

  safe_urls = set()

  for url in seed_urls:
    try:
      # Fetch and parse the HTML.
      response = urllib2.urlopen(url)
      encoding = response.headers.getparam("charset")
      html = response.read()
      if encoding:
        html = html.decode(encoding)

      parser = _HRefParser()
      parser.feed(html)
    except:
      logging.exception("Error fetching or parsing url: %s", url)
      raise

    # Looks for all hrefs.
    for relative_url in parser.hrefs:
      if not relative_url:
        continue

      absolute_url = urlparse.urljoin(url, relative_url)
      if not _AbsoluteUrlHasSaneScheme(absolute_url):
        continue
      safe_urls.add(absolute_url)

  # Sort the urls, to make them easier to view in bulk.
  safe_urls_list = list(safe_urls)
  safe_urls_list.sort()

  print json.dumps(safe_urls_list, indent=2, separators=(",", ":"))

if __name__ == "__main__":
  GenerateSafeUrls()
