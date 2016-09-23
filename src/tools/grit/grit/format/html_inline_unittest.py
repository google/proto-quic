#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''Unit tests for grit.format.html_inline'''


import os
import re
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

import unittest

from grit import util
from grit.format import html_inline


class HtmlInlineUnittest(unittest.TestCase):
  '''Unit tests for HtmlInline.'''

  def testGetResourceFilenames(self):
    '''Tests that all included files are returned by GetResourceFilenames.'''

    files = {
      'index.html': '''
      <!DOCTYPE HTML>
      <html>
        <head>
          <link rel="stylesheet" href="test.css">
          <link rel="stylesheet"
              href="really-long-long-long-long-long-test.css">
        </head>
        <body>
          <include src="test.html">
          <include
              src="really-long-long-long-long-long-test-file-omg-so-long.html">
          <iron-icon src="[[icon]]"></iron-icon><!-- Should be ignored. -->
          <iron-icon src="{{src}}"></iron-icon><!-- Also ignored. -->
        </body>
      </html>
      ''',

      'test.html': '''
      <include src="test2.html">
      ''',

      'really-long-long-long-long-long-test-file-omg-so-long.html': '''
      <!-- This really long named resource should be included. -->
      ''',

      'test2.html': '''
      <!-- This second level resource should also be included. -->
      ''',

      'test.css': '''
      .image {
        background: url('test.png');
      }
      ''',

      'really-long-long-long-long-long-test.css': '''
      a:hover {
        font-weight: bold;  /* Awesome effect is awesome! */
      }
      ''',

      'test.png': 'PNG DATA',
    }

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    resources = html_inline.GetResourceFilenames(tmp_dir.GetPath('index.html'))
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    tmp_dir.CleanUp()

  def testUnmatchedEndIfBlock(self):
    '''Tests that an unmatched </if> raises an exception.'''

    files = {
      'index.html': '''
      <!DOCTYPE HTML>
      <html>
        <if expr="lang == 'fr'">
          bonjour
        </if>
        </if>
      </html>
      ''',
    }

    tmp_dir = util.TempDir(files)

    with self.assertRaises(Exception) as cm:
      html_inline.GetResourceFilenames(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(cm.exception.message, 'Unmatched </if>')
    tmp_dir.CleanUp()

  def testCompressedJavaScript(self):
    '''Tests that ".src=" doesn't treat as a tag.'''

    files = {
      'index.js': '''
      if(i<j)a.src="hoge.png";
      ''',
    }

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    resources = html_inline.GetResourceFilenames(tmp_dir.GetPath('index.js'))
    resources.add(tmp_dir.GetPath('index.js'))
    self.failUnlessEqual(resources, source_resources)
    tmp_dir.CleanUp()

  def testInlineCSSImports(self):
    '''Tests that @import directives in inlined CSS files are inlined too.
    '''

    files = {
      'index.html': '''
      <html>
      <head>
      <link rel="stylesheet" href="css/test.css">
      </head>
      </html>
      ''',

      'css/test.css': '''
      @import url('test2.css');
      blink {
        display: none;
      }
      ''',

      'css/test2.css': '''
      .image {
        background: url('../images/test.png');
      }
      '''.strip(),

      'images/test.png': 'PNG DATA'
    }

    expected_inlined = '''
      <html>
      <head>
      <style>
      .image {
        background: url('data:image/png;base64,UE5HIERBVEE=');
      }
      blink {
        display: none;
      }
      </style>
      </head>
      </html>
      '''

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(util.normpath(filename)))

    result = html_inline.DoInline(tmp_dir.GetPath('index.html'), None)
    resources = result.inlined_files
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    self.failUnlessEqual(expected_inlined,
                         util.FixLineEnd(result.inlined_data, '\n'))

    tmp_dir.CleanUp()

  def testInlineCSSWithIncludeDirective(self):
    '''Tests that include directive in external css files also inlined'''

    files = {
      'index.html': '''
      <html>
      <head>
      <link rel="stylesheet" href="foo.css">
      </head>
      </html>
      ''',

      'foo.css': '''<include src="style.css">''',

      'style.css': '''
      <include src="style2.css">
      blink {
        display: none;
      }
      ''',
      'style2.css': '''h1 {}''',
    }

    expected_inlined = '''
      <html>
      <head>
      <style>
      h1 {}
      blink {
        display: none;
      }
      </style>
      </head>
      </html>
      '''

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    result = html_inline.DoInline(tmp_dir.GetPath('index.html'), None)
    resources = result.inlined_files
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    self.failUnlessEqual(expected_inlined,
                         util.FixLineEnd(result.inlined_data, '\n'))

  def testCssIncludedFileNames(self):
    '''Tests that all included files from css are returned'''

    files = {
      'index.html': '''
      <!DOCTYPE HTML>
      <html>
        <head>
          <link rel="stylesheet" href="test.css">
        </head>
        <body>
        </body>
      </html>
      ''',

      'test.css': '''
      <include src="test2.css">
      ''',

      'test2.css': '''
      <include src="test3.css">
      .image {
        background: url('test.png');
      }
      ''',

      'test3.css': '''h1 {}''',

      'test.png': 'PNG DATA'
    }

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    resources = html_inline.GetResourceFilenames(tmp_dir.GetPath('index.html'))
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    tmp_dir.CleanUp()

  def testInlineCSSLinks(self):
    '''Tests that only CSS files referenced via relative URLs are inlined.'''

    files = {
      'index.html': '''
      <html>
      <head>
      <link rel="stylesheet" href="foo.css">
      <link rel="stylesheet" href="chrome://resources/bar.css">
      </head>
      </html>
      ''',

      'foo.css': '''
      @import url(chrome://resources/blurp.css);
      blink {
        display: none;
      }
      ''',
    }

    expected_inlined = '''
      <html>
      <head>
      <style>
      @import url(chrome://resources/blurp.css);
      blink {
        display: none;
      }
      </style>
      <link rel="stylesheet" href="chrome://resources/bar.css">
      </head>
      </html>
      '''

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    result = html_inline.DoInline(tmp_dir.GetPath('index.html'), None)
    resources = result.inlined_files
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    self.failUnlessEqual(expected_inlined,
                         util.FixLineEnd(result.inlined_data, '\n'))

  def testFilenameVariableExpansion(self):
    '''Tests that variables are expanded in filenames before inlining.'''

    files = {
      'index.html': '''
      <html>
      <head>
      <link rel="stylesheet" href="style[WHICH].css">
      <script src="script[WHICH].js"></script>
      </head>
      <include src="tmpl[WHICH].html">
      <img src="img[WHICH].png">
      </html>
      ''',
      'style1.css': '''h1 {}''',
      'tmpl1.html': '''<h1></h1>''',
      'script1.js': '''console.log('hello');''',
      'img1.png': '''abc''',
    }

    expected_inlined = '''
      <html>
      <head>
      <style>h1 {}</style>
      <script>console.log('hello');</script>
      </head>
      <h1></h1>
      <img src="data:image/png;base64,YWJj">
      </html>
      '''

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    def replacer(var, repl):
      return lambda filename: filename.replace('[%s]' % var, repl)

    # Test normal inlining.
    result = html_inline.DoInline(
        tmp_dir.GetPath('index.html'),
        None,
        filename_expansion_function=replacer('WHICH', '1'))
    resources = result.inlined_files
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    self.failUnlessEqual(expected_inlined,
                         util.FixLineEnd(result.inlined_data, '\n'))

    # Test names-only inlining.
    result = html_inline.DoInline(
        tmp_dir.GetPath('index.html'),
        None,
        names_only=True,
        filename_expansion_function=replacer('WHICH', '1'))
    resources = result.inlined_files
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)

  def testWithCloseTags(self):
    '''Tests that close tags are removed.'''

    files = {
      'index.html': '''
      <html>
      <head>
      <link rel="stylesheet" href="style1.css"></link>
      <link rel="stylesheet" href="style2.css">
      </link>
      <link rel="stylesheet" href="style2.css"
      >
      </link>
      <script src="script1.js"></script>
      </head>
      <include src="tmpl1.html"></include>
      <include src="tmpl2.html">
      </include>
      <include src="tmpl2.html"
      >
      </include>
      <img src="img1.png">
      </html>
      ''',
      'style1.css': '''h1 {}''',
      'style2.css': '''h2 {}''',
      'tmpl1.html': '''<h1></h1>''',
      'tmpl2.html': '''<h2></h2>''',
      'script1.js': '''console.log('hello');''',
      'img1.png': '''abc''',
    }

    expected_inlined = '''
      <html>
      <head>
      <style>h1 {}</style>
      <style>h2 {}</style>
      <style>h2 {}</style>
      <script>console.log('hello');</script>
      </head>
      <h1></h1>
      <h2></h2>
      <h2></h2>
      <img src="data:image/png;base64,YWJj">
      </html>
      '''

    source_resources = set()
    tmp_dir = util.TempDir(files)
    for filename in files:
      source_resources.add(tmp_dir.GetPath(filename))

    # Test normal inlining.
    result = html_inline.DoInline(
        tmp_dir.GetPath('index.html'),
        None)
    resources = result.inlined_files
    resources.add(tmp_dir.GetPath('index.html'))
    self.failUnlessEqual(resources, source_resources)
    self.failUnlessEqual(expected_inlined,
                         util.FixLineEnd(result.inlined_data, '\n'))

if __name__ == '__main__':
  unittest.main()
