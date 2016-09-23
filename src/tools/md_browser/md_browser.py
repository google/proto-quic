#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Simple Markdown browser for a Git checkout."""
from __future__ import print_function

import SimpleHTTPServer
import SocketServer
import argparse
import codecs
import os
import re
import socket
import sys


THIS_DIR = os.path.abspath(os.path.dirname(__file__))
SRC_DIR = os.path.dirname(os.path.dirname(THIS_DIR))
sys.path.append(os.path.join(SRC_DIR, 'third_party', 'Python-Markdown'))
import markdown


def main(argv):
  parser = argparse.ArgumentParser(prog='md_browser')
  parser.add_argument('-p', '--port', type=int, default=8080,
                      help='port to run on (default = %(default)s)')
  parser.add_argument('-d', '--directory', type=str, default=SRC_DIR)
  args = parser.parse_args(argv)

  try:
    s = Server(args.port, args.directory)
    print("Listening on http://localhost:%s/" % args.port)
    if os.path.isfile(os.path.join(args.directory, 'docs', 'README.md')):
      print(" Try loading http://localhost:%s/docs/README.md" % args.port)
    elif os.path.isfile(os.path.join(args.directory, 'README.md')):
      print(" Try loading http://localhost:%s/README.md" % args.port)
    s.serve_forever()
    s.shutdown()
    return 0
  except KeyboardInterrupt:
    return 130


def _gitiles_slugify(value, _separator):
  """Convert a string (representing a section title) to URL anchor name.

  This function is passed to "toc" extension as an extension option, so we
  can emulate the way how Gitiles converts header titles to URL anchors.

  Gitiles' official documentation about the conversion is at:

  https://gerrit.googlesource.com/gitiles/+/master/Documentation/markdown.md#Named-anchors

  Args:
    value: The name of a section that is to be converted.
    _separator: Unused. This is actually a configurable string that is used
        as a replacement character for spaces in the title, typically set to
        '-'. Since we emulate Gitiles' way of slugification here, it makes
        little sense to have the separator charactor configurable.
  """

  # TODO(yutak): Implement accent removal. This does not seem easy without
  # some library. For now we just make accented characters turn into
  # underscores, just like other non-ASCII characters.

  value = value.encode('ascii', 'replace')  # Non-ASCII turns into '?'.
  value = re.sub(r'[^- a-zA-Z0-9]', '_', value)  # Non-alphanumerics to '_'.
  value = value.replace(u' ', u'-')
  value = re.sub(r'([-_])[-_]+', r'\1', value)  # Fold hyphens and underscores.
  return value


class Server(SocketServer.TCPServer):
  def __init__(self, port, top_level):
    SocketServer.TCPServer.__init__(self, ('0.0.0.0', port), Handler)
    self.port = port
    self.top_level = os.path.abspath(top_level)

  def server_bind(self):
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.socket.bind(self.server_address)


class Handler(SimpleHTTPServer.SimpleHTTPRequestHandler):
  def do_GET(self):
    path = self.path

    # strip off the repo and branch info, if present, for compatibility
    # with gitiles.
    if path.startswith('/chromium/src/+/master'):
      path = path[len('/chromium/src/+/master'):]

    full_path = os.path.abspath(os.path.join(self.server.top_level, path[1:]))

    if not full_path.startswith(self.server.top_level):
      self._DoUnknown()
    elif path == '/doc.css':
      self._DoCSS('doc.css')
    elif not os.path.exists(full_path):
      self._DoNotFound()
    elif path.lower().endswith('.md'):
      self._DoMD(path)
    elif os.path.exists(full_path + '/README.md'):
      self._DoMD(path + '/README.md')
    else:
      self._DoUnknown()

  def _DoMD(self, path):
    extensions = [
        'markdown.extensions.def_list',
        'markdown.extensions.fenced_code',
        'markdown.extensions.tables',
        'markdown.extensions.toc',
        'gitiles_ext_blocks',
    ]
    extension_configs = {
        'markdown.extensions.toc': {
            'slugify': _gitiles_slugify
        },
    }

    contents = self._Read(path[1:])
    md_fragment = markdown.markdown(contents,
                                    extensions=extensions,
                                    extension_configs=extension_configs,
                                    output_format='html4').encode('utf-8')
    try:
      self._WriteHeader('text/html')
      self._WriteTemplate('header.html')
      self.wfile.write(md_fragment)
      self._WriteTemplate('footer.html')
    except:
      raise

  def _DoCSS(self, template):
    self._WriteHeader('text/css')
    self._WriteTemplate(template)

  def _DoNotFound(self):
    self._WriteHeader('text/html')
    self.wfile.write('<html><body>%s not found</body></html>' % self.path)

  def _DoUnknown(self):
    self._WriteHeader('text/html')
    self.wfile.write('<html><body>I do not know how to serve %s.</body>'
                       '</html>' % self.path)

  def _Read(self, relpath, relative_to=None):
    if relative_to is None:
      relative_to = self.server.top_level
    assert not relpath.startswith(os.sep)
    path = os.path.join(relative_to, relpath)
    with codecs.open(path, encoding='utf-8') as fp:
      return fp.read()

  def _WriteHeader(self, content_type='text/plain'):
    self.send_response(200)
    self.send_header('Content-Type', content_type)
    self.end_headers()

  def _WriteTemplate(self, template):
    contents = self._Read(os.path.join('tools', 'md_browser', template),
                          relative_to=SRC_DIR)
    self.wfile.write(contents.encode('utf-8'))


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
