# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Public buildspec to GIT mapping."""

import re
from deps2git import SplitScmUrl

GIT_HOST = 'https://chromium.googlesource.com/'
webkit_git = GIT_HOST + 'chromium/blink.git'

# Remove the ffmpeg overrides, since the buildspec DEPS have stripped out these
# (and other) vars that they don't use, and without them in the DEPS, deps2git
# complains about missing vars.
DEPS_OVERRIDES = {
  'src/third_party/ffmpeg': None
}


# pylint: disable=W0613
def CleanDeps(deps, deps_os, include_rules, skip_child_includes, hooks):
  global webkit_git
  webkit_rev = None
  for os, deps_section in ([(None, deps)] +
                           [(os, deps_os[os]) for os in deps_os]):
    del_deps = []
    add_deps = {}
    for dep, dep_url in deps_section.iteritems():
      # Skip 'None' exclusion entries.
      if not dep_url:
        continue

      url, rev = SplitScmUrl(dep_url)

      # Some m27 DEPS have blink entries that are just paths. Prepend the host
      # info so the rest of the processing can proceed as normal.
      m = re.match('/branches/chromium/[^/]+/'
                   '(LayoutTests|Source|Tools)(/.*)?$', url)
      if m:
        dep_url = 'https://src.chromium.org/blink' + dep_url
        deps_section[dep] = dep_url
        url, rev = SplitScmUrl(dep_url)

      # During m29 (and maybe earlier), there was some fetching (and branching)
      # of just blink LayoutTests, rather than the whole repo, with entries to
      # checkout a bunch of individual sub-paths to
      # 'src/content/test/data/layout_tests/*'.
      # Consolidate all of those deps into a single, top-level 'layout_tests'
      # entry so the whole blink repo can be checkout out there (putting
      # LayoutTests in the expected 'layout_tests/LayoutTests/' path).
      m = re.match('^https?://src.chromium.org/blink/'
                   '(trunk|branches/chromium/[^/]+)/LayoutTests(/.*)?', url)
      if m:
        if not add_deps.get('src/content/test/data/layout_tests'):
          add_deps['src/content/test/data/layout_tests'] = dep_url
        del_deps.append(dep)
        continue

      # Ignore webkit sub-path entries since git checks out all in one repo,
      is_webkit = False
      if url.startswith('/trunk/deps/third_party/WebKit/'):
        is_webkit = True
      else:
        m = re.match('https?://(svn.webkit.org/repository/webkit|'
                     'src.chromium.org/blink)'
                     '/(trunk|branches/chromium/[^/]+)/', url)
        if m:
          # Don't remove 'ios' sub-path entries, which are set explicitly to
          # just pull the headers or something. Unfortunately, the sub-path
          # repos don't mirror the branches, so if the dep is for a branch, even
          # 'ios' will have to pull the full WebKit.
          if os == 'ios' and m.group(2) == 'trunk':
            continue
          is_webkit = True
          # If svn DEPS refers to the webkit.org repo, rather than blink, use
          # the old mirror of that repo instead of blink.git.
          if 'svn.webkit.org' in m.group(1):
            webkit_git = GIT_HOST + 'external/WebKit_trimmed.git'
      if is_webkit:
        if not webkit_rev:
          webkit_rev = rev
        else:
          # All the sub-path repos should be pinned to the same revision. If
          # they're not, then not sure how to decide what revision to use for
          # the umbrella git repo.
          if rev != webkit_rev:
            raise Exception('WebKit entry revision mismatch: %s != %s' %
                            (rev, webkit_rev))
        del_deps.append(dep)
        continue

      # Some older DEPS have a split selenium py/test|selenium checkout but the
      # git selenium py repo encompasses both, so delete everything except the
      # base checkout to python/selenium.
      if dep.startswith('src/third_party/webdriver/python/selenium/'):
        del_deps.append(dep)
        continue

      # Ugh. For a while during m29, there was an entry with an incomplete URL
      # and incorrect path. How this worked even once, let alone through
      # multiple releases, is a mystery.
      if url.startswith('sctp-refimpl'):
        dep_url = 'https://' + dep_url.replace('/snv/', '/svn/')
        deps_section[dep] = dep_url
        continue

    for dep in del_deps:
      del deps_section[dep]
    deps_section.update(add_deps)

  # Make sure the top-level webkit entry that's left refers to the common
  # revision from the sub-path entries, and not to the revision of the
  # top-level "placeholder" repository. webkit_rev won't be set for recent
  # DEPS, since they use the blink repo and have no webkit sub-path entries.
  if webkit_rev:
    dep_url = deps['src/third_party/WebKit']
    url, rev = SplitScmUrl(dep_url)
    deps['src/third_party/WebKit'] = '%s@%s' % (url, webkit_rev)

def SvnUrlToGitUrl(path, svn_url):
  """Convert a chromium SVN URL to a chromium Git URL."""

  match = re.match(
      '(https?://src.chromium.org/svn|svn://svn.chromium.org/chrome)(/.*)',
      svn_url)
  if match:
    svn_url = match.group(2)

  # Handle the main 'src' repo which only appears in buildspecs.
  match = re.match('/(branches/(?P<branch>[^/]+)|trunk)/src$', svn_url)
  if match:
    if match.groupdict().get('branch'):
      return (path, GIT_HOST + 'chromium/src.git', GIT_HOST,
              match.groupdict().get('branch'))
    else:
      return (path, GIT_HOST + 'chromium/src.git', GIT_HOST)

  # libvpx branches in the chrome branches area.
  match = re.match('/branches/libvpx/(?P<branch>[^/]+)', svn_url)
  if match:
    return (path, GIT_HOST + 'chromium/deps/libvpx.git', GIT_HOST,
            match.group('branch'))

  # Since the ffmpeg overrides are gone, we can't use the upstream git repo
  # (which is what those overrides referenced), so use the mirror of the svn
  # repo.
  if svn_url == '/trunk/deps/third_party/ffmpeg':
    return (path, GIT_HOST + 'chromium/deps/ffmpeg.git', GIT_HOST)

  match = re.match('/branches/ffmpeg/(?P<branch>[^/]+)', svn_url)
  if match:
    return (path, GIT_HOST + 'chromium/deps/ffmpeg.git', GIT_HOST,
            match.group('branch'))

  # openssl branches
  match = re.match('/branches/third_party/openssl/(?P<branch>[^/]+)', svn_url)
  if match:
    return (path, GIT_HOST + 'chromium/deps/openssl.git', GIT_HOST,
            match.group('branch'))

  # The webrtc repo used to be mirrored into multiple stable/trunk repos,
  # but branches were mirrored to both, so either would work here.
  match = re.match('^https?://webrtc.googlecode.com/svn/branches/([^/]+)/(.*)',
                   svn_url)
  if match:
    branch = match.group(1)
    if match.group(2) == 'src':
      repo = 'webrtc/src.git'
    else:
      repo = 'webrtc/trunk/%s.git' % match.group(2)
    return (path, GIT_HOST + 'external/%s' % repo, GIT_HOST, branch)

  # Skia also split into multiple repos, and has unusual chrome-specific branch
  # naming.
  # https://chromium.googlesource.com/external/skia/m25_1364/src.git
  match = re.match('^https?://skia.googlecode.com/svn/branches/'
                   'chrome/([^/]+)/(?:trunk/)?(.*)', svn_url)
  if match:
    branch = match.group(1)
    repo = 'skia/%s.git' % match.group(2)
    return (path, GIT_HOST + 'external/%s' % repo, GIT_HOST, 'chrome/' + branch)

  # Make the top-level webkit entry checkout the full webkit git repository,
  # which replaces all the (non-iOS) sub-path entries.
  if svn_url == '/trunk/deps/third_party/WebKit':
    return (path, webkit_git, GIT_HOST)

  # Make the top-level python/selenium entry checkout the full selenium/py git
  # repository, which replaces all the sub-path entries.
  if svn_url == 'http://selenium.googlecode.com/svn/trunk/py/selenium':
    return (path, GIT_HOST + 'external/selenium/py.git', GIT_HOST)

  # Projects that are subdirectories of the native_client repository.
  match = re.match('^https?://src.chromium.org/native_client/branches/'
                   '(?P<branch>[^/]+)/(?P<path>.*)',
                   svn_url)
  if match:
    if match.group('path'):
      repo = '%s.git' % match.group('path')
    else:
      repo = 'src/native_client.git'
    return (path, GIT_HOST + 'native_client/%s' % repo, GIT_HOST,
            match.group('branch'))

  # blink LayoutTests.
  match = re.match('^https?://src.chromium.org/blink/'
                   '(trunk|branches/(?P<branch>chromium/[^/]+))/'
                   'LayoutTests(/.*)?',
                   svn_url)
  if match:
    repo = GIT_HOST + 'chromium/blink.git'
    if match.group('branch'):
      return (path, repo, GIT_HOST, match.group('branch'))
    else:
      return (path, repo, GIT_HOST)

  # blink branches.
  match = re.match('^https?://src.chromium.org/blink/branches/'
                   '(?P<branch>chromium/[^/]+)(?P<path>/public)?/?$',
                   svn_url)
  if match:
    # ios has a special headers-only repo
    if match.group('path'):
      repo = GIT_HOST + 'chromium/blink-public.git'
    else:
      repo = GIT_HOST + 'chromium/blink.git'
    return (path, repo, GIT_HOST, match.group('branch'))

  # reference builds
  if svn_url.startswith('/trunk/deps/reference_builds/chrome'):
    return (path, GIT_HOST + 'chromium/reference_builds/chrome.git',
            GIT_HOST)
