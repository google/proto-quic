#!/usr/bin/env python
# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

# pylint: disable=relative-import

import doctest
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import arfile
import cli


ARFILE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ARFILE_DIR)


if not hasattr(subprocess, 'DEVNULL'):
  subprocess.DEVNULL = file(os.devnull, 'wb')


def filesystem_supports_unicode():
  try:
    u'\u2603'.encode(sys.getfilesystemencoding())
    return True
  except UnicodeEncodeError:
    return False


class ClosesSaveIOBytes(io.BytesIO):

  def close(self):
    _value = self.getvalue()
    self.getvalue = lambda: _value
    io.BytesIO.close(self)


AR_TEST_SIMPLE1 = (
    # ar file header
    '!<arch>\n'
    # File 1
    # ----------------------
    # (16 bytes) simple file
    'filename1       '
    # (12 bytes) modification time
    '123         '
    # (6 bytes) user id
    '1000  '
    # (6 bytes) group id
    '1000  '
    # (8 bytes) file mode
    '100640  '
    # (10 bytes) data size
    '6         '
    # (2 bytes) file magic
    '\x60\n'
    # File data
    'abc123'
    # Finished
    '')

AR_TEST_SIMPLE_UTF = (
    # ar file header
    '!<arch>\n'
    # File 1
    # ----------------------
    # (16 bytes) simple file
    '\xe2\x98\x83             '
    # (12 bytes) modification time
    '123         '
    # (6 bytes) user id
    '1000  '
    # (6 bytes) group id
    '1000  '
    # (8 bytes) file mode
    '100640  '
    # (10 bytes) data size
    '4         '
    # (2 bytes) file magic
    '\x60\n'
    # (4 bytes) File data
    '\xf0\x9f\x92\xa9'
    # Finished
    '')

AR_TEST_BSD1 = (
    # ar file header
    '!<arch>\n'
    # File 1
    # ----------------------
    # (16 bytes) BSD style filename length
    '#1/9            '
    # (12 bytes) modification time
    '1234        '
    # (6 bytes) user id
    '1001  '
    # (6 bytes) group id
    '1001  '
    # (8 bytes) file mode
    '100644  '
    # (10 bytes) data size
    '15        '
    # (2 bytes) file magic
    '\x60\n'
    # BSD style filename
    'filename1'
    # File data
    'abc123'
    # Padding
    '\n'
    # Finished
    '')

AR_TEST_BSD2 = (
    # ar file header
    '!<arch>\n'

    # File 1
    # ----------------------
    # (16 bytes) filename len
    '#1/5            '
    # (12 bytes) mtime
    '1447140471  '
    # (6 bytes) owner id
    '1000  '
    # (6 bytes) group id
    '1000  '
    # (8 bytes) file mode
    '100640  '
    # (10 bytes) Data size
    '13        '
    # (2 bytes) File magic
    '\x60\n'
    # (9 bytes) File name
    'file1'
    # (6 bytes) File data
    'contents'
    # (1 byte) Padding
    '\n'

    # File 2
    # ----------------------
    # (16 bytes) filename len
    '#1/7            '
    # (12 bytes) mtime
    '1447140471  '
    # (6 bytes) owner id
    '1000  '
    # (6 bytes) group id
    '1000  '
    # (8 bytes) file mode
    '100640  '
    # (10 bytes) Data size
    '10        '
    # (2 bytes) File magic
    '\x60\n'
    # (9 bytes) File name
    'fileabc'
    # (6 bytes) File data
    '123'
    # (0 byte) No padding
    ''

    # File 3
    # ----------------------
    # (16 bytes) filename len
    '#1/10           '
    # (12 bytes) mtime
    '1447140471  '
    # (6 bytes) owner id
    '1000  '
    # (6 bytes) group id
    '1000  '
    # (8 bytes) file mode
    '100640  '
    # (10 bytes) Data size
    '16        '
    # (2 bytes) File magic
    '\x60\n'
    # (9 bytes) File name
    'dir1/file1'
    # (6 bytes) File data
    '123abc'
    # (0 byte) No padding
    ''

    # Finished
    '')

AR_TEST_BSD_UTF = (
    # ar file header
    '!<arch>\n'
    # File 1
    # ----------------------
    # (16 bytes) BSD style filename length
    '#1/3            '
    # (12 bytes) modification time
    '1234        '
    # (6 bytes) user id
    '1001  '
    # (6 bytes) group id
    '1001  '
    # (8 bytes) file mode
    '100644  '
    # (10 bytes) data size
    '7         '
    # (2 bytes) file magic
    '\x60\n'
    # (3 bytes) BSD style filename
    '\xe2\x98\x83'
    # (4 bytes) File data
    '\xf0\x9f\x92\xa9'
    # Padding
    '\n'
    # Finished
    '')


class TestArFileReader(unittest.TestCase):

  def testSimple1(self):
    fileobj = io.BytesIO(AR_TEST_SIMPLE1)

    afri = iter(arfile.ArFileReader(fileobj))
    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_SIMPLE, ai.format)
    self.assertEqual('filename1', ai.name)
    self.assertEqual(6, ai.size)
    self.assertEqual(123, ai.mtime)
    self.assertEqual(1000, ai.uid)
    self.assertEqual(1000, ai.gid)
    self.assertEqual('0100640', oct(ai.mode))
    self.assertEqual('abc123', af.read(ai.size))

  def testSimpleUTF(self):
    fileobj = io.BytesIO(AR_TEST_SIMPLE_UTF)

    afri = iter(arfile.ArFileReader(fileobj))
    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_SIMPLE, ai.format)
    self.assertEqual(u'\u2603', ai.name)
    self.assertEqual(4, ai.size)
    self.assertEqual(123, ai.mtime)
    self.assertEqual(1000, ai.uid)
    self.assertEqual(1000, ai.gid)
    self.assertEqual('0100640', oct(ai.mode))
    self.assertEqual(u'\U0001f4a9', af.read(ai.size).decode('utf-8'))

  def testBSD1(self):
    fileobj = io.BytesIO(AR_TEST_BSD1)

    afri = iter(arfile.ArFileReader(fileobj))
    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_BSD, ai.format)
    self.assertEqual('filename1', ai.name)
    self.assertEqual(6, ai.size)
    self.assertEqual(1234, ai.mtime)
    self.assertEqual(1001, ai.uid)
    self.assertEqual(1001, ai.gid)
    self.assertEqual('0100644', oct(ai.mode))
    self.assertEqual('abc123', af.read(ai.size))

  def testBSD2(self):
    fileobj = io.BytesIO(AR_TEST_BSD2)

    afri = iter(arfile.ArFileReader(fileobj))
    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_BSD, ai.format)
    self.assertEqual('file1', ai.name)
    self.assertEqual(8, ai.size)
    self.assertEqual(1447140471, ai.mtime)
    self.assertEqual(1000, ai.uid)
    self.assertEqual(1000, ai.gid)
    self.assertEqual('0100640', oct(ai.mode))
    self.assertEqual('contents', af.read(ai.size))

    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_BSD, ai.format)
    self.assertEqual('fileabc', ai.name)
    self.assertEqual(3, ai.size)
    self.assertEqual(1447140471, ai.mtime)
    self.assertEqual(1000, ai.uid)
    self.assertEqual(1000, ai.gid)
    self.assertEqual('0100640', oct(ai.mode))
    self.assertEqual('123', af.read(ai.size))

    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_BSD, ai.format)
    self.assertEqual('dir1/file1', ai.name)
    self.assertEqual(6, ai.size)
    self.assertEqual(1447140471, ai.mtime)
    self.assertEqual(1000, ai.uid)
    self.assertEqual(1000, ai.gid)
    self.assertEqual('0100640', oct(ai.mode))
    self.assertEqual('123abc', af.read(ai.size))

  def testBSDUTF(self):
    fileobj = io.BytesIO(AR_TEST_BSD_UTF)

    afri = iter(arfile.ArFileReader(fileobj))
    ai, af = afri.next()
    self.assertIs(arfile.AR_FORMAT_BSD, ai.format)
    self.assertEqual(u'\u2603', ai.name)
    self.assertEqual(4, ai.size)
    self.assertEqual(1234, ai.mtime)
    self.assertEqual(1001, ai.uid)
    self.assertEqual(1001, ai.gid)
    self.assertEqual('0100644', oct(ai.mode))
    self.assertEqual(u'\U0001f4a9', af.read(ai.size).decode('utf-8'))


class TestArFileWriter(unittest.TestCase):

  def testSimple1(self):
    fileobj = ClosesSaveIOBytes()

    afw = arfile.ArFileWriter(fileobj)
    ai = arfile.ArInfo(
        arfile.AR_FORMAT_SIMPLE, 'filename1', 6, 123, 1000, 1000, 0100640)
    afw.addfile(ai, io.BytesIO('abc123'))
    afw.close()

    self.assertMultiLineEqual(AR_TEST_SIMPLE1, fileobj.getvalue())

  def testSimpleUTF(self):
    fileobj = ClosesSaveIOBytes()

    afw = arfile.ArFileWriter(fileobj)
    ai = arfile.ArInfo(
        arfile.AR_FORMAT_SIMPLE, u'\u2603', 4, 123, 1000, 1000, 0100640)
    afw.addfile(ai, io.BytesIO(u'\U0001f4a9'.encode('utf-8')))
    afw.close()

    self.assertMultiLineEqual(AR_TEST_SIMPLE_UTF, fileobj.getvalue())

  def testBSD1(self):
    fileobj = ClosesSaveIOBytes()

    afw = arfile.ArFileWriter(fileobj)
    ai = arfile.ArInfo(
        arfile.AR_FORMAT_BSD, 'filename1', 6, 1234, 1001, 1001, 0100644)
    afw.addfile(ai, io.BytesIO('abc123'))
    afw.close()

    self.assertMultiLineEqual(AR_TEST_BSD1, fileobj.getvalue())

  def testBSD2(self):
    fileobj = ClosesSaveIOBytes()

    afw = arfile.ArFileWriter(fileobj)
    afw.addfile(
        arfile.ArInfo.fromdefault(
            'file1', 8, arformat=arfile.AR_FORMAT_BSD),
        io.BytesIO('contents'))
    afw.addfile(
        arfile.ArInfo.fromdefault(
            'fileabc', 3, arformat=arfile.AR_FORMAT_BSD),
        io.BytesIO('123'))
    afw.addfile(
        arfile.ArInfo.fromdefault(
            'dir1/file1', 6, arformat=arfile.AR_FORMAT_BSD),
        io.BytesIO('123abc'))
    afw.close()

    self.assertMultiLineEqual(AR_TEST_BSD2, fileobj.getvalue())

  def testBSDUTF(self):
    fileobj = ClosesSaveIOBytes()

    afw = arfile.ArFileWriter(fileobj)
    ai = arfile.ArInfo(
        arfile.AR_FORMAT_BSD, u'\u2603', 4, 1234, 1001, 1001, 0100644)
    afw.addfile(ai, io.BytesIO(u'\U0001f4a9'.encode('utf-8')))
    afw.close()

    self.assertMultiLineEqual(AR_TEST_BSD_UTF, fileobj.getvalue())


class BaseTestSuite(object):

  def testSimple1(self):
    self.assertWorking(
        (
            arfile.ArInfo(
                arfile.AR_FORMAT_SIMPLE, 'filename1',
                6, 123, 1000, 1000, 0100640),
            'abc123'))

  def testSimpleUTF(self):
    self.assertWorking(
        (
            arfile.ArInfo(
                arfile.AR_FORMAT_SIMPLE, u'\u2603',
                4, 123, 1000, 1000, 0100640),
            u'\U0001f4a9'.encode('utf-8')))

  def testBSD1(self):
    self.assertWorking(
        (
            arfile.ArInfo(
                arfile.AR_FORMAT_BSD, 'filename1',
                6, 123, 1000, 1000, 0100640),
            'abc123'))

  def testBSD2(self):
    self.assertWorking(
        (
            arfile.ArInfo.fromdefault(
                'file1', 8, arformat=arfile.AR_FORMAT_BSD),
            'contents'),
        (
            arfile.ArInfo.fromdefault(
                'fileabc', 3, arformat=arfile.AR_FORMAT_BSD),
            '123'),
        (
            arfile.ArInfo.fromdefault(
                'dir1/file1', 6, arformat=arfile.AR_FORMAT_BSD),
            '123abc'))

  def testBSDUTF(self):
    self.assertWorking(
        (
            arfile.ArInfo(
                arfile.AR_FORMAT_BSD, u'\u2603',
                4, 123, 1000, 1000, 0100640),
            u'\U0001f4a9'.encode('utf-8')))

  def testMixed(self):
    self.assertWorking(
        (arfile.ArInfo.fromdefault('file1', 0), ''),
        (arfile.ArInfo.fromdefault('f f', 1), 'a'),
        (arfile.ArInfo.fromdefault('123456789abcedefa', 1), 'a'))


class TestArRoundTrip(BaseTestSuite, unittest.TestCase):

  def assertWorking(self, *initems):
    outfile = ClosesSaveIOBytes()

    afw = arfile.ArFileWriter(outfile)
    for ai, data in initems:
      assert ai.size == len(data)
      afw.addfile(ai, io.BytesIO(data))
    afw.close()

    infile = io.BytesIO(outfile.getvalue())
    afr = arfile.ArFileReader(infile)

    outitems = []
    for ai, fd in afr:
      data = fd.read(ai.size)
      outitems.append((ai, data))

    self.assertSequenceEqual(initems, outitems)


def system_has_ar():
  retcode = subprocess.call(
      'ar', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  return retcode == 1


@unittest.skipIf(not system_has_ar(), 'no ar binary found.')
class TestArExternal(BaseTestSuite, unittest.TestCase):

  def assertWorking(self, *initems):
    tf = tempfile.NamedTemporaryFile(mode='wb')
    afw = arfile.ArFileWriter(tf)

    files = []
    for ai, data in initems:
      files.append(ai.name)
      assert ai.size == len(data)
      afw.addfile(ai, io.BytesIO(data))
    afw.flush()

    output = subprocess.check_output(['ar', 't', tf.name])
    self.assertMultiLineEqual('\n'.join(files), output.decode('utf-8').strip())
    tf.close()


class TestCLI(unittest.TestCase):

  def runCLI(self, args):
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    try:
      sys.stdout = io.StringIO()
      sys.stderr = io.StringIO()
      cli.main('artool', args)
      return sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
      sys.stdout = orig_stdout
      sys.stderr = orig_stderr

  def assertCLI(self, *initems, **kw):
    extra_args = kw.get('extra_args', [])

    indir = None
    ardir = None
    outdir = None
    try:
      indir = tempfile.mkdtemp().decode(sys.getfilesystemencoding())
      ardir = tempfile.mkdtemp().decode(sys.getfilesystemencoding())
      outdir = tempfile.mkdtemp().decode(sys.getfilesystemencoding())

      arp = os.path.join(ardir, 'out.ar')
      assert not os.path.exists(arp)

      # Write out a directory tree
      files = []
      for fp, contents in initems:
        fn = os.path.join(indir, fp)
        dn = os.path.dirname(fn)
        if not os.path.exists(dn):
          os.makedirs(dn)

        with file(fn, 'wb') as f:
          f.write(contents)

        files.append(fp)

      files.sort()
      fileslist = '\n'.join(files)

      # Create an archive from a directory
      self.runCLI(['create', '--filename', arp, indir] + extra_args)
      self.assertTrue(
          os.path.exists(arp), '%s file should exists' % arp)

      # List the archive contents
      output, _ = self.runCLI(['list', '--filename', arp])
      filesoutput = '\n'.join(sorted(output[:-1].split('\n')))
      self.assertMultiLineEqual(fileslist, filesoutput)

      # Extract the archive
      os.chdir(outdir)
      self.runCLI(['extract', '--filename', arp] + extra_args)

      # Walk the directory tree and collect the extracted output
      outitems = []
      for root, _, files in os.walk(outdir):
        for fn in files:
          fp = os.path.join(root, fn)
          outitems.append([fp[len(outdir)+1:], file(fp, 'rb').read()])

      # Check the two are equal
      self.assertSequenceEqual(sorted(initems), sorted(outitems))

    finally:
      if indir:
        shutil.rmtree(indir, ignore_errors=True)
      if ardir:
        shutil.rmtree(ardir, ignore_errors=True)
      if outdir:
        shutil.rmtree(outdir, ignore_errors=True)

  def testSimple1(self):
    self.assertCLI(['file1', 'contents1'])

  def testFullStat(self):
    self.assertCLI(
        ['file1', 'contents1'],
        extra_args=['--dont-use-defaults'])

  def testMultiple(self):
    self.assertCLI(
        ['file1', 'contents1'],
        ['dir1/file2', 'contents2'],
        ['dir2/dir3/file3', 'contents3'],
        ['file4', 'contents4'],
        )

  def testUnicodeContents(self):
    self.assertCLI(['file1', u'\u2603'.encode('utf-8')])

  def testFilenameSpaces(self):
    self.assertCLI(
        ['f f1', 'contents1'],
        ['d d1/file2', 'contents2'],
        ['d d1/f f3', 'contents3'],
        ['file4', 'contents4'],
        )

  def testBigFile(self):
    self.assertCLI(['bigfile', 'data'*1024*1024*10])

  @unittest.skipIf(
      not filesystem_supports_unicode(), 'no unicode file support')
  def testUnicode(self):
    self.assertCLI([u'\u2603', u'\U0001f4a9'.encode('utf-8')])


if __name__ == '__main__':
  doctest.testmod(arfile)
  unittest.main()
