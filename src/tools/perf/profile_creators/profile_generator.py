# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Handles generating profiles and transferring them to/from mobile devices."""

import logging
import optparse
import os
import shutil
import stat
import sys
import tempfile

from profile_creators import profile_extender
from telemetry.core import discover
from telemetry.core import util
from telemetry.internal import story_runner
from telemetry.internal.browser import browser_finder
from telemetry.internal.browser import browser_options
from telemetry.internal.util import binary_manager


def _DiscoverProfileExtenderClasses():
  profile_extenders_dir = (
      os.path.abspath(
          os.path.join(
              util.GetBaseDir(), '..', 'perf',
              'profile_creators')))
  base_dir = os.path.abspath(os.path.join(profile_extenders_dir, '..'))

  profile_extenders_unfiltered = discover.DiscoverClasses(
      profile_extenders_dir, base_dir, profile_extender.ProfileExtender)

  # Remove 'extender' suffix from keys.
  profile_extenders = {}
  for test_name, test_class in profile_extenders_unfiltered.iteritems():
    assert test_name.endswith('_extender')
    test_name = test_name[:-len('_extender')]
    profile_extenders[test_name] = test_class
  return profile_extenders


def _IsPseudoFile(directory, paths):
  """Filter function for shutil.copytree() to reject socket files and symlinks
  since those can't be copied around on bots."""
  def IsSocket(full_path):
    """Check if a file at a given path is a socket."""
    try:
      if stat.S_ISSOCK(os.stat(full_path).st_mode):
        return True
    except OSError:
      # Thrown if we encounter a broken symlink.
      pass
    return False

  ignore_list = []
  for path in paths:
    full_path = os.path.join(directory, path)

    if os.path.isdir(full_path):
      continue
    if not IsSocket(full_path) and not os.path.islink(full_path):
      continue

    logging.warning('Ignoring pseudo file: %s', full_path)
    ignore_list.append(path)

  return ignore_list


class ProfileGenerator(object):
  """Generate profile.

  On desktop the generated profile is copied to the specified location so later
  runs can reuse it.
  On CrOS profile resides on cryptohome and there is no easy way to
  override it before user login. So for CrOS we just generate the profile
  every time when the benchmark starts to run.
  """

  def __init__(self, profile_extender_class, profile_name):
    self._profile_extender_class = profile_extender_class
    self._profile_name = profile_name

  def Run(self, options):
    """Kick off the process.

    Args:
      options: Instance of BrowserFinderOptions to search for proper browser.

    Returns:
      A 2-tuple (path, new_profile).

      path: The path of the generated profile or existing profile if
      --profile-dir is given. Could be None if it's generated on default
      location (e.g., cryptohome on CrOS).

      new_profile: Whether a new profile has been generated. If this is True,
      the caller is responsible for deleting the profile.
    """
    possible_browser = browser_finder.FindBrowser(options)

    if possible_browser.browser_type.startswith('cros'):
      self.Create(options, None)
      return (None, False)

    # Use the given --profile-dir.
    if options.browser_options.profile_dir:
      return (options.browser_options.profile_dir, False)

    out_dir = tempfile.mkdtemp(prefix=self._profile_name)

    self.Create(options, out_dir)
    return (out_dir, True)

  def Create(self, options, out_dir):
    """Generate profile.

    If out_dir is given, copy the generated profile to out_dir.
    Otherwise the profile is generated to its default position
    (e.g., cryptohome on CrOS).
    """

    # Leave the global options intact.
    creator_options = options.Copy()

    if out_dir:
      sys.stderr.write('Generating profile to: %s \n' % out_dir)
      # The genrated profile is copied to out_dir only if the generation is
      # successful. In the generation process a temp directory is used so
      # the default profile is not polluted on failure.
      tmp_profile_path = tempfile.mkdtemp()
      # TODO(eakuefner): Remove this after crrev.com/1874473006 rolls in.
      try:
        getattr(creator_options, 'output_profile_path')
        creator_options.output_profile_path = tmp_profile_path
      except AttributeError:
        creator_options.browser_options.output_profile_path = tmp_profile_path

    creator = self._profile_extender_class(creator_options)

    try:
      creator.Run()
    except Exception as e:
      logging.exception('Profile creation failed.')
      raise e
    else:
      sys.stderr.write('SUCCESS: Profile generated.\n')

      # Copy generated profile to final destination if out_dir is given.
      if out_dir:
        if os.path.exists(out_dir):
          shutil.rmtree(out_dir)
        shutil.copytree(tmp_profile_path,
                        out_dir, ignore=_IsPseudoFile)
        sys.stderr.write(
            "SUCCESS: Generated profile copied to: '%s'.\n" % out_dir)
    finally:
      if out_dir:
        shutil.rmtree(tmp_profile_path)


def AddCommandLineArgs(parser):
  story_runner.AddCommandLineArgs(parser)

  profile_extenders = _DiscoverProfileExtenderClasses().keys()
  legal_profile_creators = '|'.join(profile_extenders)
  group = optparse.OptionGroup(parser, 'Profile generation options')
  group.add_option('--profile-type-to-generate',
                   dest='profile_type_to_generate',
                   default=None,
                   help='Type of profile to generate. '
                   'Supported values: %s' % legal_profile_creators)
  parser.add_option_group(group)


def ProcessCommandLineArgs(parser, args):
  story_runner.ProcessCommandLineArgs(parser, args)

  if not args.profile_type_to_generate:
    parser.error('Must specify --profile-type-to-generate option.')

  profile_extenders = _DiscoverProfileExtenderClasses().keys()
  if args.profile_type_to_generate not in profile_extenders:
    legal_profile_creators = '|'.join(profile_extenders)
    parser.error('Invalid profile type, legal values are: %s.' %
                 legal_profile_creators)

  if not args.browser_type:
    parser.error('Must specify --browser option.')

  if not args.output_dir:
    parser.error('Must specify --output-dir option.')

  if args.browser_options.dont_override_profile:
    parser.error("Can't use existing profile when generating profile.")


def Main():
  binary_manager.InitDependencyManager(None)
  options = browser_options.BrowserFinderOptions()
  parser = options.CreateParser(
      '%%prog <--profile-type-to-generate=...> <--browser=...> <--output-dir>')
  AddCommandLineArgs(parser)
  _, _ = parser.parse_args()
  ProcessCommandLineArgs(parser, options)

  # Generate profile.
  profile_extenders = _DiscoverProfileExtenderClasses()
  profile_extender_class = profile_extenders[options.profile_type_to_generate]

  generator = ProfileGenerator(profile_extender_class,
                               options.profile_type_to_generate)
  generator.Create(options, options.output_dir)
  return 0
