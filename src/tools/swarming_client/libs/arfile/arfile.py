# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

import collections
import doctest
import os
import shutil
import stat
import struct

AR_MAGIC_START = '!<arch>\n'
AR_MAGIC_BIT = '\x60\n'
AR_PADDING = '\n'

AR_FORMAT_SIMPLE = ('Simple Format',)
AR_FORMAT_BSD = ('4.4BSD Format',)
AR_FORMAT_SYSV = ('System V / GNU Format',)

AR_DEFAULT_MTIME = 1447140471
AR_DEFAULT_UID = 1000
AR_DEFAULT_GID = 1000
AR_DEFAULT_MODE = 0100640 # 100640 -- Octal

_ArInfoStruct = struct.Struct('16s 12s 6s 6s 8s 10s 2s')

_ArInfoBase = collections.namedtuple('ArInfo', [
    'format', 'name', 'size', 'mtime', 'uid', 'gid', 'mode'])

class ArInfo(_ArInfoBase):
  """A ArInfo object represents one member in an ArFile.

  It does *not* contain the file's data.
  """

  @staticmethod
  def _format(path, arformat):
    u"""
    Allow forcing the format to a given type
    >>> assert ArInfo._format('a', None) == AR_FORMAT_SIMPLE
    >>> assert ArInfo._format(u'\u2603', None) == AR_FORMAT_SIMPLE
    >>> assert ArInfo._format('a', AR_FORMAT_BSD) == AR_FORMAT_BSD

    Certain file paths require the BSD format
    >>> assert ArInfo._format('f f', None) == AR_FORMAT_BSD
    >>> assert ArInfo._format('123456789abcdef..', None) == AR_FORMAT_BSD

    >>> ArInfo._format('123456789abcdef..', AR_FORMAT_SIMPLE)
    Traceback (most recent call last):
        ...
    IOError: File name too long for format!

    >>> ArInfo._format('f f', AR_FORMAT_SIMPLE)
    Traceback (most recent call last):
        ...
    IOError: File name contains forbidden character for format!
    """
    if isinstance(path, unicode):
      path = path.encode('utf-8')

    if path.startswith('#1/'):
      if not arformat:
        arformat = AR_FORMAT_BSD
      elif arformat is AR_FORMAT_SIMPLE:
        raise IOError('File name starts with special for format!')

    if len(path) >= 16:
      if arformat is None:
        arformat = AR_FORMAT_BSD
      elif arformat is AR_FORMAT_SIMPLE:
        raise IOError('File name too long for format!')

    if ' ' in path:
      if not arformat:
        arformat = AR_FORMAT_BSD
      elif arformat is AR_FORMAT_SIMPLE:
        raise IOError('File name contains forbidden character for format!')

    if arformat is None:
      arformat = AR_FORMAT_SIMPLE

    return arformat

  @property
  def needspadding(self):
    """
    >>> ArInfo(AR_FORMAT_SIMPLE, '', 10, 0, 0, 0, 0).needspadding
    False
    >>> ArInfo(AR_FORMAT_SIMPLE, '', 11, 0, 0, 0, 0).needspadding
    True
    >>> ArInfo(AR_FORMAT_BSD, 'a', 10, 0, 0, 0, 0).needspadding
    True
    >>> ArInfo(AR_FORMAT_BSD, 'ab', 10, 0, 0, 0, 0).needspadding
    False
    >>> ArInfo(AR_FORMAT_BSD, 'ab', 11, 0, 0, 0, 0).needspadding
    True
    >>> ArInfo(AR_FORMAT_BSD, 'ab', 12, 0, 0, 0, 0).needspadding
    False
    """
    return self.datasize % 2 != 0

  @property
  def datasize(self):
    """
    >>> ArInfo(AR_FORMAT_SIMPLE, '', 1, 0, 0, 0, 0).datasize
    1
    >>> ArInfo(AR_FORMAT_SIMPLE, '', 10, 0, 0, 0, 0).datasize
    10
    >>> ArInfo(AR_FORMAT_BSD, '', 1, 0, 0, 0, 0).datasize
    1
    >>> ArInfo(AR_FORMAT_BSD, 'a', 1, 0, 0, 0, 0).datasize
    2
    >>> ArInfo(AR_FORMAT_BSD, '', 10, 0, 0, 0, 0).datasize
    10
    >>> ArInfo(AR_FORMAT_BSD, 'abc', 10, 0, 0, 0, 0).datasize
    13
    """
    if self.format is AR_FORMAT_SIMPLE:
      return self.size
    elif self.format is AR_FORMAT_BSD:
      return len(self.name)+self.size
    assert False, 'Unknown format %r' % self.format

  @classmethod
  def fromfileobj(cls, fileobj, fullparse=True):
    """Create and return a ArInfo object from fileobj.

    Raises IOError if the buffer is invalid.
    """
    buf = fileobj.read(_ArInfoStruct.size)
    if not buf:
      return None

    if len(buf) < _ArInfoStruct.size:
      raise IOError(
          'not enough data for header, got %r, needed %r' % (
              len(buf), _ArInfoStruct.size))

    name, mtime, uid, gid, mode, datasize, magic = _ArInfoStruct.unpack(buf)

    datasize = int(datasize)
    if fullparse:
      mtime = int(mtime)
      uid = int(uid)
      gid = int(gid)
      mode = int(mode, 8)

    if name.startswith('#1/'):
      arformat = AR_FORMAT_BSD

      try:
        filenamesize = int(name[3:])
      except ValueError:
        raise IOError('invalid file name length: %r' % name[3:])

      filename = fileobj.read(filenamesize)
      if len(filename) != filenamesize:
        raise IOError(
            'not enough data for filename, got %r, needed %r' % (
                len(name), filenamesize))

      filesize = datasize - filenamesize

    elif name.startswith('/'):
      arformat = AR_FORMAT_SYSV
      raise SystemError('%s format is not supported.' % arformat)

    else:
      arformat = AR_FORMAT_SIMPLE
      filename = name.strip()
      filesize = datasize

    if magic != AR_MAGIC_BIT:
      raise IOError('file magic invalid, got %r, needed %r' % (
          magic, AR_MAGIC_BIT))

    return cls(
        arformat, filename.decode('utf-8'), filesize, mtime, uid, gid, mode)

  @classmethod
  def frompath(cls, path, arformat=None, cwd=None):
    """Return an ArInfo object from a file path for information."""
    fp = path
    if cwd:
      fp = os.path.join(cwd, path)
    st = os.stat(fp)

    if not stat.S_ISREG(st.st_mode):
      raise IOError('Only work on regular files.')

    return cls(
        cls._format(path, arformat), path,
        st.st_size, st.st_mtime, st.st_uid, st.st_gid, st.st_mode)

  @classmethod
  def fromdefault(cls, path, size, arformat=None):
    """Return an ArInfo object using name and size (with defaults elsewhere).

    Only a file's name and content are needed to create the ArInfo, all of the
    modification time, user, group and mode information will be set to default
    values. This means that you don't need to perform an expensive stat the
    file.

    >>> ai = ArInfo.fromdefault('abc123', 10)
    >>> ai.name
    'abc123'
    >>> ai.size
    10
    >>> assert ai.mtime == AR_DEFAULT_MTIME
    >>> assert ai.uid == AR_DEFAULT_UID
    >>> assert ai.gid == AR_DEFAULT_GID
    >>> assert ai.mode == AR_DEFAULT_MODE
    """
    return cls(
        cls._format(path, arformat), path, size,
        AR_DEFAULT_MTIME, AR_DEFAULT_UID, AR_DEFAULT_GID, AR_DEFAULT_MODE)

  def tofileobj(self, fileobj):
    """Write an ArInfo object to file like object."""
    # File name, 16 bytes
    name = self.name.encode('utf-8')
    if self.format is AR_FORMAT_SIMPLE:
      assert len(name) < 16
      fileobj.write('%-16s' % name)
      datasize = self.size
    elif self.format is AR_FORMAT_BSD:
      fileobj.write('#1/%-13s' % str(len(name)))
      datasize = self.size + len(name)

    # Modtime, 12 bytes
    fileobj.write('%-12i' % self.mtime)
    # Owner ID, 6 bytes
    fileobj.write('%-6i' % self.uid)
    # Group ID, 6 bytes
    fileobj.write('%-6i' % self.gid)
    # File mode, 8 bytes
    fileobj.write('%-8o' % self.mode)
    # File size, 10 bytes
    fileobj.write('%-10s' % datasize)
    # File magic, 2 bytes
    fileobj.write(AR_MAGIC_BIT)

    # Filename - BSD variant
    if self.format is AR_FORMAT_BSD:
      fileobj.write(name)


class ArFileReader(object):
  """Read an ar archive from the given input buffer."""

  def __init__(self, fileobj, fullparse=True):
    self.fullparse = fullparse
    self.fileobj = fileobj

    magic = self.fileobj.read(len(AR_MAGIC_START))
    if magic != AR_MAGIC_START:
      raise IOError(
          'Not an ar file, invalid magic, got %r, wanted %r.' % (
              magic, AR_MAGIC_START))

  def __iter__(self):
    while True:
      if self.fileobj.closed:
        raise IOError('Tried to read after the file closed.')
      ai = ArInfo.fromfileobj(self.fileobj, self.fullparse)
      if not ai:
        return

      start = self.fileobj.tell()
      yield ai, self.fileobj
      end = self.fileobj.tell()

      read = end - start
      # If the reader didn't touch the input buffer, seek past the file.
      if not read:
        self.fileobj.seek(ai.size, os.SEEK_CUR)
      elif read != ai.size:
        raise IOError(
            'Wrong amount of data read from fileobj! got %i, wanted %i' % (
                read, ai.size))

      if ai.needspadding:
        padding = self.fileobj.read(len(AR_PADDING))
        if padding != AR_PADDING:
          raise IOError(
              'incorrect padding, got %r, wanted %r' % (
                  padding, AR_PADDING))

  def close(self):
    """Close the archive.

    Will close the output buffer.
    """
    self.fileobj.close()


class ArFileWriter(object):
  """Write an ar archive from the given output buffer."""

  def __init__(self, fileobj):
    self.fileobj = fileobj
    self.fileobj.write(AR_MAGIC_START)

  def addfile(self, arinfo, fileobj=None):
    if not fileobj and arinfo.size:
      raise ValueError('Need to supply fileobj if file is non-zero in size.')

    arinfo.tofileobj(self.fileobj)
    if fileobj:
      shutil.copyfileobj(fileobj, self.fileobj, arinfo.size)

    if arinfo.needspadding:
      self.fileobj.write(AR_PADDING)

  def flush(self):
    """Flush the output buffer."""
    self.fileobj.flush()

  def close(self):
    """Close the archive.

    Will close the output buffer."""
    self.fileobj.close()


def is_arfile(name):
  with file(name, 'rb') as f:
    return f.read(len(AR_MAGIC_START)) == AR_MAGIC_START


# pylint: disable=redefined-builtin
def open(name=None, mode='r', fileobj=None):
  if name is None and fileobj is None:
    raise ValueError('Nothing to open!')

  if name is not None:
    if fileobj is not None:
      raise ValueError('Provided both a file name and file object!')
    fileobj = file(name, mode+'b')

  if 'b' not in fileobj.mode:
    raise ValueError('File object not open in binary mode.')

  if mode == 'rb':
    return ArFileReader(fileobj)
  elif mode == 'wb':
    return ArFileWriter(fileobj)

  raise ValueError('Unknown file mode.')


if __name__ == '__main__':
  doctest.testmod()
