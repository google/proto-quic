# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""This file implements Named Caches."""

import contextlib
import logging
import optparse
import os
import random
import re
import string

from utils import lru
from utils import file_path
from utils import fs
from utils import threading_utils


# Keep synced with task_request.py
CACHE_NAME_RE = re.compile(ur'^[a-z0-9_]{1,4096}$')
MAX_CACHE_SIZE = 50


class Error(Exception):
  """Named cache specific error."""


class CacheManager(object):
  """Manages cache directories exposed to a task as symlinks.

  A task can specify that caches should be present on a bot. A cache is
  tuple (name, path), where
    name is a short identifier that describes the contents of the cache, e.g.
      "git_v8" could be all git repositories required by v8 builds, or
      "build_chromium" could be build artefacts of the Chromium.
    path is a directory path relative to the task run dir. It will be mapped
      to the cache directory persisted on the bot.
  """

  def __init__(self, root_dir):
    """Initializes NamedCaches.

    |root_dir| is a directory for persistent cache storage.
    """
    assert file_path.isabs(root_dir), root_dir
    self.root_dir = unicode(root_dir)
    self._lock = threading_utils.LockWithAssert()
    # LRU {cache_name -> cache_location}
    # It is saved to |root_dir|/state.json.
    self._lru = None

  @contextlib.contextmanager
  def open(self, time_fn=None):
    """Opens NamedCaches for mutation operations, such as request or trim.

    Only on caller can open the cache manager at a time. If the same thread
    calls this function after opening it earlier, the call will deadlock.

    time_fn is a function that returns timestamp (float) and used to take
    timestamps when new caches are requested.

    Returns a context manager that must be closed as soon as possible.
    """
    with self._lock:
      state_path = os.path.join(self.root_dir, u'state.json')
      assert self._lru is None, 'acquired lock, but self._lru is not None'
      if os.path.isfile(state_path):
        try:
          self._lru = lru.LRUDict.load(state_path)
        except ValueError:
          logging.exception('failed to load named cache state file')
          logging.warning('deleting named caches')
          file_path.rmtree(self.root_dir)
      self._lru = self._lru or lru.LRUDict()
      if time_fn:
        self._lru.time_fn = time_fn
      try:
        yield
      finally:
        file_path.ensure_tree(self.root_dir)
        self._lru.save(state_path)
        self._lru = None

  def __len__(self):
    """Returns number of items in the cache.

    Requires NamedCache to be open.
    """
    return len(self._lru)

  def request(self, name):
    """Returns an absolute path to the directory of the named cache.

    Creates a cache directory if it does not exist yet.

    Requires NamedCache to be open.
    """
    self._lock.assert_locked()
    assert isinstance(name, basestring), name
    path = self._lru.get(name)
    create_named_link = False
    if path is None:
      path = self._allocate_dir()
      create_named_link = True
      logging.info('Created %r for %r', path, name)
    abs_path = os.path.join(self.root_dir, path)

    # TODO(maruel): That's weird, it should exist already.
    file_path.ensure_tree(abs_path)
    self._lru.add(name, path)

    if create_named_link:
      # Create symlink <root_dir>/<named>/<name> -> <root_dir>/<short name>
      # for user convenience.
      named_path = self._get_named_path(name)
      if os.path.exists(named_path):
        file_path.remove(named_path)
      else:
        file_path.ensure_tree(os.path.dirname(named_path))
      logging.info('Symlink %r to %r', named_path, abs_path)
      fs.symlink(abs_path, named_path)

    return abs_path

  def get_oldest(self):
    """Returns name of the LRU cache or None.

    Requires NamedCache to be open.
    """
    self._lock.assert_locked()
    try:
      return self._lru.get_oldest()[0]
    except KeyError:
      return None

  def get_timestamp(self, name):
    """Returns timestamp of last use of an item.

    Requires NamedCache to be open.

    Raises KeyError if cache is not found.
    """
    self._lock.assert_locked()
    assert isinstance(name, basestring), name
    return self._lru.get_timestamp(name)

  @contextlib.contextmanager
  def create_symlinks(self, root, named_caches):
    """Creates symlinks in |root| for the specified named_caches.

    named_caches must be a list of (name, path) tuples.

    Requires NamedCache to be open.

    Raises Error if cannot create a symlink.
    """
    self._lock.assert_locked()
    for name, path in named_caches:
      logging.info('Named cache %r -> %r', name, path)
      try:
        _validate_named_cache_path(path)
        symlink_path = os.path.abspath(os.path.join(root, path))
        file_path.ensure_tree(os.path.dirname(symlink_path))
        requested = self.request(name)
        logging.info('Symlink %r to %r', symlink_path, requested)
        fs.symlink(requested, symlink_path)
      except (OSError, Error) as ex:
        raise Error(
            'cannot create a symlink for cache named "%s" at "%s": %s' % (
              name, symlink_path, ex))

  def delete_symlinks(self, root, named_caches):
    """Deletes symlinks from |root| for the specified named_caches.

    named_caches must be a list of (name, path) tuples.
    """
    for name, path in named_caches:
      logging.info('Unlinking named cache "%s"', name)
      try:
        _validate_named_cache_path(path)
        symlink_path = os.path.abspath(os.path.join(root, path))
        fs.unlink(symlink_path)
      except (OSError, Error) as ex:
        raise Error(
            'cannot unlink cache named "%s" at "%s": %s' % (
              name, symlink_path, ex))

  def trim(self, min_free_space):
    """Purges cache.

    Removes cache directories that were not accessed for a long time
    until there is enough free space and the number of caches is sane.

    If min_free_space is None, disk free space is not checked.

    Requires NamedCache to be open.

    Returns:
      Number of caches deleted.
    """
    self._lock.assert_locked()
    if not os.path.isdir(self.root_dir):
      return 0

    total = 0
    free_space = 0
    if min_free_space:
      free_space = file_path.get_free_space(self.root_dir)
    while ((min_free_space and free_space < min_free_space)
           or len(self._lru) > MAX_CACHE_SIZE):
      logging.info(
          'Making space for named cache %s > %s or %s > %s',
          free_space, min_free_space, len(self._lru), MAX_CACHE_SIZE)
      try:
        name, (path, _) = self._lru.get_oldest()
      except KeyError:
        return total
      named_dir = self._get_named_path(name)
      if fs.islink(named_dir):
        fs.unlink(named_dir)
      path_abs = os.path.join(self.root_dir, path)
      if os.path.isdir(path_abs):
        logging.info('Removing named cache %s', path_abs)
        file_path.rmtree(path_abs)
      if min_free_space:
        free_space = file_path.get_free_space(self.root_dir)
      self._lru.pop(name)
      total += 1
    return total

  _DIR_ALPHABET = string.ascii_letters + string.digits

  def _allocate_dir(self):
    """Creates and returns relative path of a new cache directory."""
    # We randomly generate directory names that have two lower/upper case
    # letters or digits. Total number of possibilities is (26*2 + 10)^2 = 3844.
    abc_len = len(self._DIR_ALPHABET)
    tried = set()
    while len(tried) < 1000:
      i = random.randint(0, abc_len * abc_len - 1)
      rel_path = (
        self._DIR_ALPHABET[i / abc_len] +
        self._DIR_ALPHABET[i % abc_len])
      if rel_path in tried:
        continue
      abs_path = os.path.join(self.root_dir, rel_path)
      if not fs.exists(abs_path):
        return rel_path
      tried.add(rel_path)
    raise Error('could not allocate a new cache dir, too many cache dirs')

  def _get_named_path(self, name):
    return os.path.join(self.root_dir, 'named', name)


def add_named_cache_options(parser):
  group = optparse.OptionGroup(parser, 'Named caches')
  group.add_option(
      '--named-cache',
      dest='named_caches',
      action='append',
      nargs=2,
      default=[],
      help='A named cache to request. Accepts two arguments, name and path. '
           'name identifies the cache, must match regex [a-z0-9_]{1,4096}. '
           'path is a path relative to the run dir where the cache directory '
           'must be symlinked to. '
           'This option can be specified more than once.')
  group.add_option(
      '--named-cache-root',
      help='Cache root directory. Default=%default')
  parser.add_option_group(group)


def process_named_cache_options(parser, options):
  """Validates named cache options and returns a CacheManager."""
  if options.named_caches and not options.named_cache_root:
    parser.error('--named-cache is specified, but --named-cache-root is empty')
  for name, path in options.named_caches:
    if not CACHE_NAME_RE.match(name):
      parser.error(
          'cache name "%s" does not match %s' % (name, CACHE_NAME_RE.pattern))
    if not path:
      parser.error('cache path cannot be empty')
  if options.named_cache_root:
    return CacheManager(os.path.abspath(options.named_cache_root))
  return None


def _validate_named_cache_path(path):
  if os.path.isabs(path):
    raise Error('named cache path must not be absolute')
  if '..' in path.split(os.path.sep):
    raise Error('named cache path must not contain ".."')
