# Copyright 2015 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Wraps os, os.path and shutil functions to work around MAX_PATH on Windows."""

import __builtin__
import inspect
import os
import shutil
import sys


if sys.platform == 'win32':


  import ctypes
  CreateSymbolicLinkW = ctypes.windll.kernel32.CreateSymbolicLinkW
  CreateSymbolicLinkW.argtypes = (
      ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32)
  CreateSymbolicLinkW.restype = ctypes.c_ubyte
  DeleteFile = ctypes.windll.kernel32.DeleteFileW
  DeleteFile.argtypes = (ctypes.c_wchar_p,)
  DeleteFile.restype = ctypes.c_bool
  GetFileAttributesW = ctypes.windll.kernel32.GetFileAttributesW
  GetFileAttributesW.argtypes = (ctypes.c_wchar_p,)
  GetFileAttributesW.restype = ctypes.c_uint
  RemoveDirectory = ctypes.windll.kernel32.RemoveDirectoryW
  RemoveDirectory.argtypes = (ctypes.c_wchar_p,)
  RemoveDirectory.restype = ctypes.c_bool


  def extend(path):
    """Adds '\\\\?\\' when given an absolute path so the MAX_PATH (260) limit is
    not enforced.
    """
    assert os.path.isabs(path), path
    assert isinstance(path, unicode), path
    prefix = u'\\\\?\\'
    return path if path.startswith(prefix) else prefix + path


  def trim(path):
    """Removes '\\\\?\\' when receiving a path."""
    assert isinstance(path, unicode), path
    prefix = u'\\\\?\\'
    if path.startswith(prefix):
      path = path[len(prefix):]
    assert os.path.isabs(path), path
    return path


  def islink(path):
    """Proper implementation of islink() for Windows.

    The stdlib is broken.
    https://msdn.microsoft.com/library/windows/desktop/aa365682.aspx
    """
    FILE_ATTRIBUTE_REPARSE_POINT = 1024
    return bool(GetFileAttributesW(extend(path)) & FILE_ATTRIBUTE_REPARSE_POINT)


  def symlink(source, link_name):
    """Creates a symlink on Windows 7 and later.

    This function will only work once SeCreateSymbolicLinkPrivilege has been
    enabled. See file_path.enable_symlink().

    Useful material:
    CreateSymbolicLinkW:
      https://msdn.microsoft.com/library/windows/desktop/aa363866.aspx
    UAC and privilege stripping:
      https://msdn.microsoft.com/library/bb530410.aspx
    Privilege constants:
      https://msdn.microsoft.com/library/windows/desktop/bb530716.aspx
    """
    # TODO(maruel): This forces always creating absolute path symlinks.
    source = extend(source)
    flags = 1 if os.path.isdir(source) else 0
    if not CreateSymbolicLinkW(extend(link_name), source, flags):
      raise WindowsError()  # pylint: disable=undefined-variable


  def unlink(path):
    """Removes a symlink on Windows 7 and later.

    Does not delete the link source.

    If path is not a link, but a non-empty directory, will fail with a
    WindowsError.

    Useful material:
    CreateSymbolicLinkW:
      https://msdn.microsoft.com/library/windows/desktop/aa363866.aspx
    DeleteFileW:
      https://msdn.microsoft.com/en-us/library/windows/desktop/aa363915(v=vs.85).aspx
    RemoveDirectoryW:
      https://msdn.microsoft.com/en-us/library/windows/desktop/aa365488(v=vs.85).aspx
    """
    path = extend(path)
    if os.path.isdir(path):
      if not RemoveDirectory(path):
        # pylint: disable=undefined-variable
        raise WindowsError('could not remove directory "%s"' % path)
    else:
      if not DeleteFile(path):
        # pylint: disable=undefined-variable
        raise WindowsError('could not delete file "%s"' % path)


  def walk(top, *args, **kwargs):
    return os.walk(extend(top), *args, **kwargs)


else:


  def extend(path):
    """Convert the path back to utf-8.

    In some rare case, concatenating str and unicode may cause a
    UnicodeEncodeError because the default encoding is 'ascii'.
    """
    assert os.path.isabs(path), path
    assert isinstance(path, unicode), path
    return path.encode('utf-8')


  def trim(path):
    """Path mangling is not needed on POSIX."""
    assert os.path.isabs(path), path
    assert isinstance(path, str), path
    return path.decode('utf-8')


  def islink(path):
    return os.path.islink(extend(path))


  def symlink(source, link_name):
    return os.symlink(source, extend(link_name))

  def unlink(path):
    return os.unlink(extend(path))

  def walk(top, *args, **kwargs):
    for root, dirs, files in os.walk(extend(top), *args, **kwargs):
      yield trim(root), dirs, files


## builtin


def open(path, *args, **kwargs):  # pylint: disable=redefined-builtin
  return __builtin__.open(extend(path), *args, **kwargs)


## os


def link(source, link_name):
  return os.link(extend(source), extend(link_name))


def rename(old, new):
  return os.rename(extend(old), extend(new))


def renames(old, new):
  return os.renames(extend(old), extend(new))


## shutil


def copy2(src, dst):
  return shutil.copy2(extend(src), extend(dst))


def rmtree(path, *args, **kwargs):
  return shutil.rmtree(extend(path), *args, **kwargs)


## The rest


def _get_lambda(func):
  return lambda path, *args, **kwargs: func(extend(path), *args, **kwargs)


def _is_path_fn(func):
  return (inspect.getargspec(func)[0] or [None]) == 'path'


_os_fns = (
  'access', 'chdir', 'chflags', 'chroot', 'chmod', 'chown', 'lchflags',
  'lchmod', 'lchown', 'listdir', 'lstat', 'mknod', 'mkdir', 'makedirs',
  'remove', 'removedirs', 'rmdir', 'stat', 'statvfs', 'unlink', 'utime')

_os_path_fns = (
  'exists', 'lexists', 'getatime', 'getmtime', 'getctime', 'getsize', 'isfile',
  'isdir', 'ismount')


for _fn in _os_fns:
  if hasattr(os, _fn):
    sys.modules[__name__].__dict__.setdefault(
        _fn, _get_lambda(getattr(os, _fn)))


for _fn in _os_path_fns:
  if hasattr(os.path, _fn):
    sys.modules[__name__].__dict__.setdefault(
        _fn, _get_lambda(getattr(os.path, _fn)))
