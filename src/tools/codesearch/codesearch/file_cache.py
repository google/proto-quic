# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import hashlib
import threading
import tempfile
import os
import datetime

# A key/value store that stores objects to disk in temporary objects
# for 30 minutes.


class FileCache:

  def __init__(self, cache_dir=None, expiration_in_minutes=30):

    # Protects |self| but individual file objects in |store| are not
    # protected once its returned from |_file_for|.
    self.lock = threading.Lock()

    # Dictionary mapping a URL to a tuple containing a file object and a
    # timestamp. The timestamp notes the creation time.
    self.store = {}

    # Directory containing cache files. If |cache_dir| is None, then each
    # file is created independently using tempfile.TemporaryFile().
    self.cache_dir = cache_dir

    # Garbage collector timer.
    self.timer = threading.Timer(15 * 60, self.gc)
    self.timer.start()

    self.expiration = datetime.timedelta(minutes=expiration_in_minutes)

    if cache_dir and not os.path.exists(cache_dir):
      if not os.path.isabs(cache_dir):
        raise ValueError('|cache_dir| should be an absolute path')
      os.mkdirs(cache_dir)

  def _file_for(self, url, create=False):
    with self.lock:
      if url in self.store:
        f, _ = self.store[url]
        f.seek(0)

      elif create and self.cache_dir is None:
        f = tempfile.TemporaryFile()
        f.seek(0)

      elif self.cache_dir:
        deterministic_filename = os.path.join(self.cache_dir,
                                              hashlib.sha1(url).hexdigest())
        if os.path.exists(deterministic_filename):
          st = os.stat(deterministic_filename)
          if create:
            f = open(deterministic_filename, 'w+')
          elif datetime.datetime.utcfromtimestamp(st.st_mtime) + \
                  self.expiration > datetime.datetime.now():
            f = open(deterministic_filename, 'r+')
            self.store[url] = (f,
                               datetime.datetime.utcfromtimestamp(st.st_mtime))
          else:
            # Existing file has expired.
            os.remove(deterministic_filename)
            return None
        else:
          if create:
            f = open(deterministic_filename, 'w+')
          else:
            return None
      else:
        return None

      if url not in self.store:
        self.store[url] = (f, datetime.datetime.now())
      return f

  def put(self, url, data):
    f = self._file_for(url, create=True)
    f.write(data)
    f.flush()

  def get(self, url):
    f = self._file_for(url, create=False)
    if f is None:
      return ''
    f.seek(0)
    return f.read()

  def gc(self):
    dir_to_purge = None
    expiration = None
    with self.lock:
      expired = datetime.datetime.now() - self.expiration
      remove = []
      for url, (_, timestamp) in self.store.items():
        if timestamp < expired:
          remove.append(url)
      for url in remove:
        self.store.pop(url)
      self.timer = threading.Timer(15 * 60, self.gc)
      self.timer.start()
      dir_to_purge = self.cache_dir
      expiration = self.expiration

    # This part doesn't require a lock on |self|.
    if not dir_to_purge:
      return

    now = datetime.datetime.now()
    for entry in os.listdir(dir_to_purge):
      full_path = os.path.join(dir_to_purge, entry)
      st = os.stat(full_path)
      expires_on = datetime.datetime.utcfromtimestamp(st.st_mtime) + expiration
      if expires_on < now:
        os.remove(full_path)

  def close(self):
    self.timer.cancel()
