# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""RPC compatible subprocess-type module.

This module defined both a task-side process class as well as a controller-side
process wrapper for easier access and usage of the task-side process.
"""

import logging
import os
import subprocess
import sys
import threading
import time

from legion.lib import common_lib
from utils import subprocess42


class TimeoutError(Exception):
  pass


class ControllerProcessWrapper(object):
  """Controller-side process wrapper class.

  This class provides a more intuitive interface to task-side processes
  than calling the methods directly using the RPC object.
  """

  def __init__(self, rpc, cmd, verbose=False, detached=False, cwd=None,
               key=None, shell=None):
    logging.debug('Creating a process with cmd=%s', cmd)
    self._rpc = rpc
    self._key = rpc.subprocess.Process(cmd, key)
    logging.debug('Process created with key=%s', self._key)
    if verbose:
      self._rpc.subprocess.SetVerbose(self._key)
    if detached:
      self._rpc.subprocess.SetDetached(self._key)
    if cwd:
      self._rpc.subprocess.SetCwd(self._key, cwd)
    if shell:
      self._rpc.subprocess.SetShell(self._key)
    self._rpc.subprocess.Start(self._key)

  @property
  def key(self):
    return self._key

  def Terminate(self):
    logging.debug('Terminating process %s', self._key)
    return self._rpc.subprocess.Terminate(self._key)

  def Kill(self):
    logging.debug('Killing process %s', self._key)
    self._rpc.subprocess.Kill(self._key)

  def Delete(self):
    return self._rpc.subprocess.Delete(self._key)

  def GetReturncode(self):
    return self._rpc.subprocess.GetReturncode(self._key)

  def ReadStdout(self):
    """Returns all stdout since the last call to ReadStdout.

    This call allows the user to read stdout while the process is running.
    However each call will flush the local stdout buffer. In order to make
    multiple calls to ReadStdout and to retain the entire output the results
    of this call will need to be buffered in the calling code.
    """
    return self._rpc.subprocess.ReadStdout(self._key)

  def ReadStderr(self):
    """Returns all stderr read since the last call to ReadStderr.

    See ReadStdout for additional details.
    """
    return self._rpc.subprocess.ReadStderr(self._key)

  def ReadOutput(self):
    """Returns the (stdout, stderr) since the last Read* call.

    See ReadStdout for additional details.
    """
    return self._rpc.subprocess.ReadOutput(self._key)

  def Wait(self, timeout=None):
    return self._rpc.subprocess.Wait(self._key, timeout)

  def Poll(self):
    return self._rpc.subprocess.Poll(self._key)

  def GetPid(self):
    return self._rpc.subprocess.GetPid(self._key)


class Process(object):
  """Implements a task-side non-blocking subprocess.

  This non-blocking subprocess allows the caller to continue operating while
  also able to interact with this subprocess based on a key returned to
  the caller at the time of creation.

  Creation args are set via Set* methods called after calling Process but
  before calling Start. This is due to a limitation of the XML-RPC
  implementation not supporting keyword arguments.
  """

  _processes = {}
  _process_next_id = 0
  _creation_lock = threading.Lock()

  def __init__(self, cmd, key):
    self.stdout = ''
    self.stderr = ''
    self.key = key
    self.cmd = cmd
    self.proc = None
    self.cwd = None
    self.shell = False
    self.verbose = False
    self.detached = False
    self.complete = False
    self.data_lock = threading.Lock()
    self.stdout_file = open(self._CreateOutputFilename('stdout'), 'wb+')
    self.stderr_file = open(self._CreateOutputFilename('stderr'), 'wb+')

  def _CreateOutputFilename(self, fname):
    return os.path.join(common_lib.GetOutputDir(), '%s.%s' % (self.key, fname))

  def __str__(self):
    return '%r, cwd=%r, verbose=%r, detached=%r' % (
        self.cmd, self.cwd, self.verbose, self.detached)

  def _reader(self):
    for pipe, data in self.proc.yield_any():
      with self.data_lock:
        if pipe == 'stdout':
          self.stdout += data
          self.stdout_file.write(data)
          self.stdout_file.flush()
          if self.verbose:
            sys.stdout.write(data)
        else:
          self.stderr += data
          self.stderr_file.write(data)
          self.stderr_file.flush()
          if self.verbose:
            sys.stderr.write(data)
    self.complete = True

  @classmethod
  def KillAll(cls):
    for key in cls._processes:
      cls.Kill(key)

  @classmethod
  def Process(cls, cmd, key=None):
    with cls._creation_lock:
      if not key:
        key = 'Process%d' % cls._process_next_id
        cls._process_next_id += 1
      if key in cls._processes:
        raise KeyError('Key %s already in use' % key)
      logging.debug('Creating process %s with cmd %r', key, cmd)
      cls._processes[key] = cls(cmd, key)
    return key

  def _Start(self):
    logging.info('Starting process %s', self)
    self.proc = subprocess42.Popen(self.cmd, stdout=subprocess42.PIPE,
                                   stderr=subprocess42.PIPE,
                                   detached=self.detached, cwd=self.cwd,
                                   shell=self.shell)
    threading.Thread(target=self._reader).start()

  @classmethod
  def Start(cls, key):
    cls._processes[key]._Start()

  @classmethod
  def SetCwd(cls, key, cwd):
    """Sets the process's cwd."""
    logging.debug('Setting %s cwd to %s', key, cwd)
    cls._processes[key].cwd = cwd

  @classmethod
  def SetShell(cls, key):
    """Sets the process's shell arg to True."""
    logging.debug('Setting %s.shell = True', key)
    cls._processes[key].shell = True

  @classmethod
  def SetDetached(cls, key):
    """Creates a detached process."""
    logging.debug('Setting %s.detached = True', key)
    cls._processes[key].detached = True

  @classmethod
  def SetVerbose(cls, key):
    """Sets the stdout and stderr to be emitted locally."""
    logging.debug('Setting %s.verbose = True', key)
    cls._processes[key].verbose = True

  @classmethod
  def Terminate(cls, key):
    logging.debug('Terminating process %s', key)
    cls._processes[key].proc.terminate()

  @classmethod
  def Kill(cls, key):
    logging.debug('Killing process %s', key)
    cls._processes[key].proc.kill()

  @classmethod
  def Delete(cls, key):
    if cls.GetReturncode(key) is None:
      logging.warning('Killing %s before deleting it', key)
      cls.Kill(key)
    logging.debug('Deleting process %s', key)
    cls._processes.pop(key)

  @classmethod
  def GetReturncode(cls, key):
    return cls._processes[key].proc.returncode

  @classmethod
  def ReadStdout(cls, key):
    """Returns all stdout since the last call to ReadStdout.

    This call allows the user to read stdout while the process is running.
    However each call will flush the local stdout buffer. In order to make
    multiple calls to ReadStdout and to retain the entire output the results
    of this call will need to be buffered in the calling code.
    """
    proc = cls._processes[key]
    with proc.data_lock:
      # Perform a "read" on the stdout data
      stdout = proc.stdout
      proc.stdout = ''
    return stdout

  @classmethod
  def ReadStderr(cls, key):
    """Returns all stderr read since the last call to ReadStderr.

    See ReadStdout for additional details.
    """
    proc = cls._processes[key]
    with proc.data_lock:
      # Perform a "read" on the stderr data
      stderr = proc.stderr
      proc.stderr = ''
    return stderr

  @classmethod
  def ReadOutput(cls, key):
    """Returns the (stdout, stderr) since the last Read* call.

    See ReadStdout for additional details.
    """
    return cls.ReadStdout(key), cls.ReadStderr(key)

  @classmethod
  def Wait(cls, key, timeout=None):
    """Wait for the process to complete.

    We wait for all of the output to be written before returning. This solves
    a race condition found on Windows where the output can lag behind the
    wait call.

    Raises:
      TimeoutError if the process doesn't finish in the specified timeout.
    """
    end = None if timeout is None else timeout + time.time()
    while end is None or end > time.time():
      if cls._processes[key].complete:
        return
      time.sleep(0.05)
    raise TimeoutError()

  @classmethod
  def Poll(cls, key):
    return cls._processes[key].proc.poll()

  @classmethod
  def GetPid(cls, key):
    return cls._processes[key].proc.pid
