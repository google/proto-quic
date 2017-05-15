# Copyright 2016 The LUCI Authors. All rights reserved.
# Use of this source code is governed under the Apache License, Version 2.0
# that can be found in the LICENSE file.

"""Fetches CIPD client and installs packages."""

import contextlib
import hashlib
import json
import logging
import optparse
import os
import platform
import sys
import tempfile
import time
import urllib

from utils import file_path
from utils import fs
from utils import net
from utils import subprocess42
from utils import tools
import isolated_format
import isolateserver


# .exe on Windows.
EXECUTABLE_SUFFIX = '.exe' if sys.platform == 'win32' else ''


if sys.platform == 'win32':
  def _ensure_batfile(client_path):
    base, _ = os.path.splitext(client_path)
    with open(base+".bat", 'w') as f:
      f.write('\n'.join([  # python turns \n into CRLF
        '@set CIPD="%~dp0cipd.exe"',
        '@shift',
        '@%CIPD% %*'
      ]))
else:
  def _ensure_batfile(_client_path):
    pass


class Error(Exception):
  """Raised on CIPD errors."""


def add_cipd_options(parser):
  group = optparse.OptionGroup(parser, 'CIPD')
  group.add_option(
      '--cipd-enabled',
      help='Enable CIPD client bootstrap. Implied by --cipd-package.',
      action='store_true',
      default=False)
  group.add_option(
      '--cipd-server',
      help='URL of the CIPD server. '
           'Only relevant with --cipd-enabled or --cipd-package.')
  group.add_option(
      '--cipd-client-package',
      help='Package name of CIPD client with optional parameters described in '
           '--cipd-package help. '
           'Only relevant with --cipd-enabled or --cipd-package. '
           'Default: "%default"',
      default='infra/tools/cipd/${platform}')
  group.add_option(
      '--cipd-client-version',
      help='Version of CIPD client. '
           'Only relevant with --cipd-enabled or --cipd-package. '
           'Default: "%default"',
      default='latest')
  group.add_option(
      '--cipd-package',
      dest='cipd_packages',
      help='A CIPD package to install. '
           'Format is "<path>:<package_name>:<version>". '
           '"path" is installation directory relative to run_dir, '
           'defaults to ".". '
           '"package_name" may have ${platform} and/or ${os_ver} parameters. '
           '${platform} will be expanded to "<os>-<architecture>" and '
           '${os_ver} will be expanded to OS version name. '
           'The option can be specified multiple times.',
      action='append',
      default=[])
  group.add_option(
      '--cipd-cache',
      help='CIPD cache directory, separate from isolate cache. '
           'Only relevant with --cipd-enabled or --cipd-package. '
           'Default: "%default".',
      default='')
  parser.add_option_group(group)


def validate_cipd_options(parser, options):
  """Calls parser.error on first found error among cipd options."""
  if options.cipd_packages:
    options.cipd_enabled = True

  if not options.cipd_enabled:
    return

  for pkg in options.cipd_packages:
    parts = pkg.split(':', 2)
    if len(parts) != 3:
      parser.error('invalid package "%s": must have at least 2 colons' % pkg)
    _path, name, version = parts
    if not name:
      parser.error('invalid package "%s": package name is not specified' % pkg)
    if not version:
      parser.error('invalid package "%s": version is not specified' % pkg)

  if not options.cipd_server:
    parser.error('cipd is enabled, --cipd-server is required')

  if not options.cipd_client_package:
    parser.error(
        'cipd is enabled, --cipd-client-package is required')
  if not options.cipd_client_version:
    parser.error(
        'cipd is enabled, --cipd-client-version is required')


class CipdClient(object):
  """Installs packages."""

  def __init__(self, binary_path, package_name, instance_id, service_url):
    """Initializes CipdClient.

    Args:
      binary_path (str): path to the CIPD client binary.
      package_name (str): the CIPD package name for the client itself.
      instance_id (str): the CIPD instance_id for the client itself.
      service_url (str): if not None, URL of the CIPD backend that overrides
        the default one.
    """
    self.binary_path = binary_path
    self.package_name = package_name
    self.instance_id = instance_id
    self.service_url = service_url

  def ensure(
      self, site_root, packages, cache_dir=None, tmp_dir=None, timeout=None):
    """Ensures that packages installed in |site_root| equals |packages| set.

    Blocking call.

    Args:
      site_root (str): where to install packages.
      packages: dict of subdir -> list of (package_template, version) tuples.
      cache_dir (str): if set, cache dir for cipd binary own cache.
        Typically contains packages and tags.
      tmp_dir (str): if not None, dir for temp files.
      timeout (int): if not None, timeout in seconds for this function to run.

    Returns:
      Pinned packages in the form of {subdir: [(package_name, package_id)]},
      which correspond 1:1 with the input packages argument.

    Raises:
      Error if could not install packages or timed out.
    """
    timeoutfn = tools.sliding_timeout(timeout)
    logging.info('Installing packages %r into %s', packages, site_root)

    ensure_file_handle, ensure_file_path = tempfile.mkstemp(
        dir=tmp_dir, prefix=u'cipd-ensure-file-', suffix='.txt')
    json_out_file_handle, json_file_path = tempfile.mkstemp(
      dir=tmp_dir, prefix=u'cipd-ensure-result-', suffix='.json')
    os.close(json_out_file_handle)

    try:
      try:
        for subdir, pkgs in sorted(packages.iteritems()):
          if '\n' in subdir:
            raise Error(
              'Could not install packages; subdir %r contains newline' % subdir)
          os.write(ensure_file_handle, '@Subdir %s\n' % (subdir,))
          for pkg, version in pkgs:
            pkg = render_package_name_template(pkg)
            os.write(ensure_file_handle, '%s %s\n' % (pkg, version))
      finally:
        os.close(ensure_file_handle)

      cmd = [
        self.binary_path, 'ensure',
        '-root', site_root,
        '-ensure-file', ensure_file_path,
        '-verbose',  # this is safe because cipd-ensure does not print a lot
        '-json-output', json_file_path,
      ]
      if cache_dir:
        cmd += ['-cache-dir', cache_dir]
      if self.service_url:
        cmd += ['-service-url', self.service_url]

      logging.debug('Running %r', cmd)
      process = subprocess42.Popen(
          cmd, stdout=subprocess42.PIPE, stderr=subprocess42.PIPE)
      output = []
      for pipe_name, line in process.yield_any_line(timeout=0.1):
        to = timeoutfn()
        if to is not None and to <= 0:
          raise Error(
              'Could not install packages; took more than %d seconds' % timeout)
        if not pipe_name:
          # stdout or stderr was closed, but yield_any_line still may have
          # something to yield.
          continue
        output.append(line)
        if pipe_name == 'stderr':
          logging.debug('cipd client: %s', line)
        else:
          logging.info('cipd client: %s', line)

      exit_code = process.wait(timeout=timeoutfn())
      if exit_code != 0:
        raise Error(
            'Could not install packages; exit code %d\noutput:%s' % (
            exit_code, '\n'.join(output)))
      with open(json_file_path) as jfile:
        result_json = json.load(jfile)
      return {
        subdir: [(x['package'], x['instance_id']) for x in pins]
        for subdir, pins in result_json['result'].iteritems()
      }
    finally:
      fs.remove(ensure_file_path)
      fs.remove(json_file_path)


def get_platform():
  """Returns ${platform} parameter value.

  Borrowed from
  https://chromium.googlesource.com/infra/infra/+/aaf9586/build/build.py#204
  """
  # linux, mac or windows.
  platform_variant = {
    'darwin': 'mac',
    'linux2': 'linux',
    'win32': 'windows',
  }.get(sys.platform)
  if not platform_variant:
    raise Error('Unknown OS: %s' % sys.platform)

  # amd64, 386, etc.
  machine = platform.machine().lower()
  platform_arch = {
    'amd64': 'amd64',
    'i386': '386',
    'i686': '386',
    'x86': '386',
    'x86_64': 'amd64',
  }.get(machine)
  if not platform_arch:
    if machine.startswith('arm'):
      platform_arch = 'armv6l'
    else:
      platform_arch = 'amd64' if sys.maxsize > 2**32 else '386'
  return '%s-%s' % (platform_variant, platform_arch)


def get_os_ver():
  """Returns ${os_ver} parameter value.

  Examples: 'ubuntu14_04' or 'mac10_9' or 'win6_1'.

  Borrowed from
  https://chromium.googlesource.com/infra/infra/+/aaf9586/build/build.py#204
  """
  if sys.platform == 'darwin':
    # platform.mac_ver()[0] is '10.9.5'.
    dist = platform.mac_ver()[0].split('.')
    return 'mac%s_%s' % (dist[0], dist[1])

  if sys.platform == 'linux2':
    # platform.linux_distribution() is ('Ubuntu', '14.04', ...).
    dist = platform.linux_distribution()
    return '%s%s' % (dist[0].lower(), dist[1].replace('.', '_'))

  if sys.platform == 'win32':
    # platform.version() is '6.1.7601'.
    dist = platform.version().split('.')
    return 'win%s_%s' % (dist[0], dist[1])
  raise Error('Unknown OS: %s' % sys.platform)


def render_package_name_template(template):
  """Expands template variables in a CIPD package name template."""
  return (template
      .lower()  # Package names are always lower case
      .replace('${platform}', get_platform())
      .replace('${os_ver}', get_os_ver()))


def _check_response(res, fmt, *args):
  """Raises Error if response is bad."""
  if not res:
    raise Error('%s: no response' % (fmt % args))

  if res.get('status') != 'SUCCESS':
    raise Error('%s: %s' % (
        fmt % args,
        res.get('error_message') or 'status is %s' % res.get('status')))


def resolve_version(cipd_server, package_name, version, timeout=None):
  """Resolves a package instance version (e.g. a tag) to an instance id."""
  url = '%s/_ah/api/repo/v1/instance/resolve?%s' % (
      cipd_server,
      urllib.urlencode({
        'package_name': package_name,
        'version': version,
      }))
  res = net.url_read_json(url, timeout=timeout)
  _check_response(res, 'Could not resolve version %s:%s', package_name, version)
  instance_id = res.get('instance_id')
  if not instance_id:
    raise Error('Invalid resolveVersion response: no instance id')
  return instance_id


def get_client_fetch_url(service_url, package_name, instance_id, timeout=None):
  """Returns a fetch URL of CIPD client binary contents.

  Raises:
    Error if cannot retrieve fetch URL.
  """
  # Fetch the URL of the binary from CIPD backend.
  package_name = render_package_name_template(package_name)
  url = '%s/_ah/api/repo/v1/client?%s' % (service_url, urllib.urlencode({
    'package_name': package_name,
    'instance_id': instance_id,
  }))
  res = net.url_read_json(url, timeout=timeout)
  _check_response(
      res, 'Could not fetch CIPD client %s:%s',package_name, instance_id)
  fetch_url = res.get('client_binary', {}).get('fetch_url')
  if not fetch_url:
    raise Error('Invalid fetchClientBinary response: no fetch_url')
  return fetch_url


def _fetch_cipd_client(disk_cache, instance_id, fetch_url, timeoutfn):
  """Fetches cipd binary to |disk_cache|.

  Retries requests with exponential back-off.

  Raises:
    Error if could not fetch content.
  """
  sleep_time = 1
  for attempt in xrange(5):
    if attempt > 0:
      if timeoutfn() is not None and timeoutfn() < sleep_time:
        raise Error('Could not fetch CIPD client: timeout')
      logging.warning('Will retry to fetch CIPD client in %ds', sleep_time)
      time.sleep(sleep_time)
      sleep_time *= 2

    try:
      res = net.url_open(fetch_url, timeout=timeoutfn())
      if res:
        disk_cache.write(instance_id, res.iter_content(64 * 1024))
        return
    except net.TimeoutError as ex:
      raise Error('Could not fetch CIPD client: %s', ex)
    except net.NetError as ex:
      logging.warning(
          'Could not fetch CIPD client on attempt #%d: %s', attempt + 1, ex)

  raise Error('Could not fetch CIPD client after 5 retries')


@contextlib.contextmanager
def get_client(service_url, package_name, version, cache_dir, timeout=None):
  """Returns a context manager that yields a CipdClient. A blocking call.

  Upon exit from the context manager, the client binary may be deleted
  (if the internal cache is full).

  Args:
    service_url (str): URL of the CIPD backend.
    package_name (str): package name template of the CIPD client.
    version (str): version of CIPD client package.
    cache_dir: directory to store instance cache, version cache
      and a hardlink to the client binary.
    timeout (int): if not None, timeout in seconds for this function.

  Yields:
    CipdClient.

  Raises:
    Error if CIPD client version cannot be resolved or client cannot be fetched.
  """
  timeoutfn = tools.sliding_timeout(timeout)

  package_name = render_package_name_template(package_name)

  # Resolve version to instance id.
  # Is it an instance id already? They look like HEX SHA1.
  if isolated_format.is_valid_hash(version, hashlib.sha1):
    instance_id = version
  elif ':' in version: # it's an immutable tag
    # version_cache is {version_digest -> instance id} mapping.
    # It does not take a lot of disk space.
    version_cache = isolateserver.DiskCache(
        unicode(os.path.join(cache_dir, 'versions')),
        isolateserver.CachePolicies(0, 0, 300),
        hashlib.sha1,
        trim=True)
    with version_cache:
      version_cache.cleanup()
      # Convert |version| to a string that may be used as a filename in disk
      # cache by hashing it.
      version_digest = hashlib.sha1(version).hexdigest()
      try:
        with version_cache.getfileobj(version_digest) as f:
          instance_id = f.read()
      except isolateserver.CacheMiss:
        instance_id = resolve_version(
            service_url, package_name, version, timeout=timeoutfn())
        version_cache.write(version_digest, instance_id)
  else: # it's a ref
    instance_id = resolve_version(
        service_url, package_name, version, timeout=timeoutfn())

  # instance_cache is {instance_id -> client binary} mapping.
  # It is bounded by 5 client versions.
  instance_cache = isolateserver.DiskCache(
      unicode(os.path.join(cache_dir, 'clients')),
      isolateserver.CachePolicies(0, 0, 5),
      hashlib.sha1,
      trim=True)
  with instance_cache:
    instance_cache.cleanup()
    if instance_id not in instance_cache:
      logging.info('Fetching CIPD client %s:%s', package_name, instance_id)
      fetch_url = get_client_fetch_url(
          service_url, package_name, instance_id, timeout=timeoutfn())
      _fetch_cipd_client(instance_cache, instance_id, fetch_url, timeoutfn)

    # A single host can run multiple swarming bots, but ATM they do not share
    # same root bot directory. Thus, it is safe to use the same name for the
    # binary.
    cipd_bin_dir = unicode(os.path.join(cache_dir, 'bin'))
    binary_path = os.path.join(cipd_bin_dir, 'cipd' + EXECUTABLE_SUFFIX)
    if fs.isfile(binary_path):
      file_path.remove(binary_path)
    else:
      file_path.ensure_tree(cipd_bin_dir)

    with instance_cache.getfileobj(instance_id) as f:
      isolateserver.putfile(f, binary_path, 0511)  # -r-x--x--x

    _ensure_batfile(binary_path)

    yield CipdClient(
        binary_path,
        package_name=package_name,
        instance_id=instance_id,
        service_url=service_url)


def parse_package_args(packages):
  """Parses --cipd-package arguments.

  Assumes |packages| were validated by validate_cipd_options.

  Returns:
    A list of [(path, package_name, version), ...]
  """
  result = []
  for pkg in packages:
    path, name, version = pkg.split(':', 2)
    if not name:
      raise Error('Invalid package "%s": package name is not specified' % pkg)
    if not version:
      raise Error('Invalid package "%s": version is not specified' % pkg)
    result.append((path, name, version))
  return result
