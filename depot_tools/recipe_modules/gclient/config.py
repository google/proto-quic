# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import types

from recipe_engine.config import config_item_context, ConfigGroup, BadConf
from recipe_engine.config import ConfigList, Dict, Single, Static, Set, List

from . import api as gclient_api


def BaseConfig(USE_MIRROR=True, GIT_MODE=False, CACHE_DIR=None,
               PATCH_PROJECT=None, BUILDSPEC_VERSION=None,
               **_kwargs):
  deps = '.DEPS.git' if GIT_MODE else 'DEPS'
  cache_dir = str(CACHE_DIR) if GIT_MODE and CACHE_DIR else None
  return ConfigGroup(
    solutions = ConfigList(
      lambda: ConfigGroup(
        name = Single(basestring),
        url = Single(basestring),
        deps_file = Single(basestring, empty_val=deps, required=False,
                           hidden=False),
        managed = Single(bool, empty_val=True, required=False, hidden=False),
        custom_deps = Dict(value_type=(basestring, types.NoneType)),
        custom_vars = Dict(value_type=basestring),
        safesync_url = Single(basestring, required=False),

        revision = Single(
            (basestring, gclient_api.RevisionResolver),
            required=False, hidden=True),
      )
    ),
    deps_os = Dict(value_type=basestring),
    hooks = List(basestring),
    target_os = Set(basestring),
    target_os_only = Single(bool, empty_val=False, required=False),
    cache_dir = Static(cache_dir, hidden=False),

    # If supplied, use this as the source root (instead of the first solution's
    # checkout).
    src_root = Single(basestring, required=False, hidden=True),

    # Maps 'solution' -> build_property
    got_revision_mapping = Dict(hidden=True),

    # Addition revisions we want to pass in.  For now theres a duplication
    # of code here of setting custom vars AND passing in --revision. We hope
    # to remove custom vars later.
    revisions = Dict(
        value_type=(basestring, gclient_api.RevisionResolver),
        hidden=True),

    # TODO(iannucci): HACK! The use of None here to indicate that we apply this
    #   to the solution.revision field is really terrible. I mostly blame
    #   gclient.
    # Maps 'parent_build_property' -> 'custom_var_name'
    # Maps 'parent_build_property' -> None
    # If value is None, the property value will be applied to
    # solutions[0].revision. Otherwise, it will be applied to
    # solutions[0].custom_vars['custom_var_name']
    parent_got_revision_mapping = Dict(hidden=True),
    delete_unversioned_trees = Single(bool, empty_val=True, required=False),

    # Check out refs/branch-heads.
    # TODO (machenbach): Only implemented for bot_update atm.
    with_branch_heads = Single(
        bool,
        empty_val=False,
        required=False,
        hidden=True),

    GIT_MODE = Static(bool(GIT_MODE)),
    USE_MIRROR = Static(bool(USE_MIRROR)),
    PATCH_PROJECT = Static(str(PATCH_PROJECT), hidden=True),
    BUILDSPEC_VERSION= Static(BUILDSPEC_VERSION, hidden=True),
  )

config_ctx = config_item_context(BaseConfig)

def ChromiumSvnSubURL(c, *pieces):
  BASES = ('https://src.chromium.org',
           'svn://svn-mirror.golo.chromium.org')
  return '/'.join((BASES[c.USE_MIRROR],) + pieces)

def ChromiumGitURL(_c, *pieces):
  return '/'.join(('https://chromium.googlesource.com',) + pieces)

def ChromiumSrcURL(c):
  # TODO(phajdan.jr): Move to proper repo and add coverage.
  if c.GIT_MODE:  # pragma: no cover
    return ChromiumGitURL(c, 'chromium', 'src.git')
  else:
    return ChromiumSvnSubURL(c, 'chrome', 'trunk', 'src')

def BlinkURL(c):
  # TODO(phajdan.jr): Move to proper repo and add coverage.
  if c.GIT_MODE:  # pragma: no cover
    return ChromiumGitURL(c, 'chromium', 'blink.git')
  else:
    return ChromiumSvnSubURL(c, 'blink', 'trunk')

def ChromeSvnSubURL(c, *pieces):
  BASES = ('svn://svn.chromium.org',
           'svn://svn-mirror.golo.chromium.org')
  return '/'.join((BASES[c.USE_MIRROR],) + pieces)

# TODO(phajdan.jr): Move to proper repo and add coverage.
def ChromeInternalGitURL(_c, *pieces):  # pragma: no cover
  return '/'.join(('https://chrome-internal.googlesource.com',) + pieces)

def ChromeInternalSrcURL(c):
  # TODO(phajdan.jr): Move to proper repo and add coverage.
  if c.GIT_MODE:  # pragma: no cover
    return ChromeInternalGitURL(c, 'chrome', 'src-internal.git')
  else:
    return ChromeSvnSubURL(c, 'chrome-internal', 'trunk', 'src-internal')

def mirror_only(c, obj, default=None):
  return obj if c.USE_MIRROR else (default or obj.__class__())

@config_ctx()
def chromium_bare(c):
  s = c.solutions.add()
  s.name = 'src'
  s.url = ChromiumSrcURL(c)
  s.custom_vars = mirror_only(c, {
    'googlecode_url': 'svn://svn-mirror.golo.chromium.org/%s',
    'nacl_trunk': 'svn://svn-mirror.golo.chromium.org/native_client/trunk',
    'sourceforge_url': 'svn://svn-mirror.golo.chromium.org/%(repo)s',
    'webkit_trunk': BlinkURL(c)})
  m = c.got_revision_mapping
  m['src'] = 'got_revision'
  m['src/native_client'] = 'got_nacl_revision'
  m['src/tools/swarming_client'] = 'got_swarming_client_revision'
  m['src/v8'] = 'got_v8_revision'
  m['src/third_party/angle'] = 'got_angle_revision'
  m['src/third_party/webrtc'] = 'got_webrtc_revision'

  p = c.parent_got_revision_mapping
  p['parent_got_revision'] = None
  p['parent_got_angle_revision'] = 'angle_revision'
  p['parent_got_nacl_revision'] = 'nacl_revision'
  p['parent_got_swarming_client_revision'] = 'swarming_revision'
  p['parent_got_v8_revision'] = 'v8_revision'
  p['parent_got_webrtc_revision'] = 'webrtc_revision'

  # Patch project revisions are applied whenever patch_project is set. E.g. if
  # a v8 stand-alone patch is sent to a chromium trybot, patch_project is v8
  # and can be used to sync v8 to HEAD instead of the pinned chromium
  # version.
  patch_project_revisions = {
    'v8': ('src/v8', 'HEAD'),
  }

  patch_revision = patch_project_revisions.get(c.PATCH_PROJECT)
  # TODO(phajdan.jr): Move to proper repo and add coverage.
  if patch_revision:  # pragma: no cover
    c.revisions[patch_revision[0]] = patch_revision[1]

@config_ctx(includes=['chromium_bare'])
def chromium_empty(c):
  c.solutions[0].deps_file = ''  # pragma: no cover

@config_ctx(includes=['chromium_bare'])
def chromium(c):
  s = c.solutions[0]
  s.custom_deps = mirror_only(c, {})

@config_ctx(includes=['chromium'])
def chromium_lkcr(c):
  # TODO(phajdan.jr): Add git hashes for LKCR crbug.com/349277.
  if c.GIT_MODE:
    raise BadConf('Git has problems with safesync_url and LKCR, '
                  'crbug.com/349277 crbug.com/109191')  # pragma: no cover
  s = c.solutions[0]
  s.safesync_url = 'https://build.chromium.org/p/chromium/lkcr-status/lkgr'
  # TODO(hinoka): Once lkcr exists and is a tag, it should just be lkcr
  #               rather than origin/lkcr.
  s.revision = 'origin/lkcr'

@config_ctx(includes=['chromium'])
def chromium_lkgr(c):
  s = c.solutions[0]
  safesync_url = 'https://chromium-status.appspot.com/lkgr'
  if c.GIT_MODE:  # pragma: no cover
    safesync_url = 'https://chromium-status.appspot.com/git-lkgr'
    raise BadConf('Git has problems with safesync_url, crbug.com/109191.')
  s.safesync_url = safesync_url
  s.revision = 'origin/lkgr'

@config_ctx(includes=['chromium_bare'])
def android_bare(c):
  # We inherit from chromium_bare to get the got_revision mapping.
  # NOTE: We don't set a specific got_revision mapping for src/repo.
  del c.solutions[0]
  c.got_revision_mapping['src'] = 'got_src_revision'
  s = c.solutions.add()
  s.deps_file = '.DEPS.git'

# TODO(iannucci,vadimsh): Switch this to src-limited
@config_ctx()
def chrome_internal(c):
  s = c.solutions.add()
  s.name = 'src-internal'
  s.url = ChromeInternalSrcURL(c)
  # Remove some things which are generally not needed
  s.custom_deps = {
    "src/data/autodiscovery" : None,
    "src/data/page_cycler" : None,
    "src/tools/grit/grit/test/data" : None,
    "src/chrome/test/data/perf/frame_rate/private" : None,
    "src/data/mozilla_js_tests" : None,
    "src/chrome/test/data/firefox2_profile/searchplugins" : None,
    "src/chrome/test/data/firefox2_searchplugins" : None,
    "src/chrome/test/data/firefox3_profile/searchplugins" : None,
    "src/chrome/test/data/firefox3_searchplugins" : None,
    "src/chrome/test/data/ssl/certs" : None,
    "src/data/mach_ports" : None,
    "src/data/esctf" : None,
    "src/data/selenium_core" : None,
    "src/chrome/test/data/plugin" : None,
    "src/data/memory_test" : None,
    "src/data/tab_switching" : None,
    "src/chrome/test/data/osdd" : None,
    "src/webkit/data/bmp_decoder":None,
    "src/webkit/data/ico_decoder":None,
    "src/webkit/data/test_shell/plugins":None,
    "src/webkit/data/xbm_decoder":None,
  }

@config_ctx(includes=['chromium'])
def blink(c):
  c.solutions[0].revision = 'HEAD'
  del c.solutions[0].custom_deps
  c.revisions['src/third_party/WebKit'] = 'HEAD'

@config_ctx(includes=['chromium'])
def blink_or_chromium(c):
  c.solutions[0].revision = gclient_api.ProjectRevisionResolver('chromium')
  del c.solutions[0].custom_deps
  c.revisions['src/third_party/WebKit'] = \
      gclient_api.ProjectRevisionResolver(
          'webkit', parent_got_revision='parent_got_webkit_revision')

# TODO(phajdan.jr): Move to proper repo and add coverage.
@config_ctx(includes=['chromium'])
def blink_merged(c):  # pragma: no cover
  c.solutions[0].url = \
      'https://chromium.googlesource.com/playground/chromium-blink-merge.git'

@config_ctx()
def android(c):
  c.target_os.add('android')

@config_ctx(includes=['chromium', 'chrome_internal'])
def ios(c):
  c.target_os.add('ios')

@config_ctx(includes=['chromium'])
def show_v8_revision(c):
  # Have the V8 revision appear in the web UI instead of Chromium's.
  c.got_revision_mapping['src'] = 'got_cr_revision'
  c.got_revision_mapping['src/v8'] = 'got_revision'
  # Needed to get the testers to properly sync the right revision.
  c.parent_got_revision_mapping['parent_got_revision'] = 'got_revision'

@config_ctx(includes=['chromium'])
def v8_bleeding_edge_git(c):
  c.solutions[0].revision = 'HEAD'
  # TODO(machenbach): If bot_update is activated for all v8-chromium bots
  # and there's no gclient fallback, then the following line can be removed.
  c.solutions[0].custom_vars['v8_branch'] = 'branches/bleeding_edge'
  c.revisions['src/v8'] = 'HEAD'

@config_ctx()
def v8_canary(c):
  c.revisions['src/v8'] = 'origin/canary'

@config_ctx(includes=['chromium'])
def oilpan(c):  # pragma: no cover
  if c.GIT_MODE:
    raise BadConf("Oilpan requires SVN for now")
  c.solutions[0].custom_vars = {
    'webkit_trunk': ChromiumSvnSubURL(c, 'blink', 'branches', 'oilpan')
  }
  c.solutions[0].custom_vars['sourceforge_url'] = mirror_only(
    c,
    'svn://svn-mirror.golo.chromium.org/%(repo)s',
    'svn://svn.chromium.org/%(repo)s'
  )

  c.revisions['src/third_party/WebKit'] = 'HEAD'
  c.solutions[0].revision = '197341'

  c.solutions[0].custom_deps = {
    'src/chrome/tools/test/reference_build/chrome_linux' :
      ChromiumSvnSubURL(c, 'blink', 'branches', 'oilpan', 'Tools',
                        'reference_build', 'chrome_linux')
  }
  del c.got_revision_mapping['src']
  c.got_revision_mapping['src/third_party/WebKit/Source'] = 'got_revision'

@config_ctx(includes=['oilpan', 'chrome_internal'])
def oilpan_internal(c):  # pragma: no cover
  # Add back the oilpan data dependencies
  needed_components_internal = [
    "src/data/memory_test",
    "src/data/mozilla_js_tests",
    "src/data/page_cycler",
    "src/data/tab_switching",
    "src/webkit/data/bmp_decoder",
    "src/webkit/data/ico_decoder",
    "src/webkit/data/test_shell/plugins",
    "src/webkit/data/xbm_decoder",
  ]
  for key in needed_components_internal:
    del c.solutions[1].custom_deps[key]

@config_ctx()
def nacl(c):
  s = c.solutions.add()
  s.name = 'native_client'
  s.url = ChromiumGitURL(c, 'native_client', 'src', 'native_client.git')
  m = c.got_revision_mapping
  m['native_client'] = 'got_revision'

@config_ctx()
def webports(c):
  s = c.solutions.add()
  s.name = 'src'
  s.url = ChromiumGitURL(c, 'webports.git')
  m = c.got_revision_mapping
  m['src'] = 'got_revision'

@config_ctx()
def wasm_llvm(c):
  s = c.solutions.add()
  s.name = 'src'
  s.url = ChromiumGitURL(
      c, 'external', 'github.com', 'WebAssembly', 'waterfall.git')
  m = c.got_revision_mapping
  m['src'] = 'got_waterfall_revision'
  c.revisions['src'] = 'origin/master'

@config_ctx()
def gyp(c):
  s = c.solutions.add()
  s.name = 'gyp'
  s.url = ChromiumGitURL(c, 'external', 'gyp.git')
  m = c.got_revision_mapping
  m['gyp'] = 'got_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def build(c):  # pragma: no cover
  if not c.GIT_MODE:
    raise BadConf('build only supports git')
  s = c.solutions.add()
  s.name = 'build'
  s.url = ChromiumGitURL(c, 'chromium', 'tools', 'build.git')
  m = c.got_revision_mapping
  m['build'] = 'got_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def depot_tools(c):  # pragma: no cover
  if not c.GIT_MODE:
    raise BadConf('depot_tools only supports git')
  s = c.solutions.add()
  s.name = 'depot_tools'
  s.url = ChromiumGitURL(c, 'chromium', 'tools', 'depot_tools.git')
  m = c.got_revision_mapping
  m['depot_tools'] = 'got_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def skia(c):  # pragma: no cover
  if not c.GIT_MODE:
    raise BadConf('skia only supports git')
  s = c.solutions.add()
  s.name = 'skia'
  s.url = 'https://skia.googlesource.com/skia.git'
  m = c.got_revision_mapping
  m['skia'] = 'got_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def chrome_golo(c): # pragma: no cover
  if not c.GIT_MODE:
    raise BadConf('chrome_golo only supports git')
  s = c.solutions.add()
  s.name = 'chrome_golo'
  s.url = 'https://chrome-internal.googlesource.com/chrome-golo/chrome-golo.git'
  c.got_revision_mapping['chrome_golo'] = 'got_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def build_internal(c):
  if not c.GIT_MODE:  # pragma: no cover
    raise BadConf('build_internal only supports git')
  s = c.solutions.add()
  s.name = 'build_internal'
  s.url = 'https://chrome-internal.googlesource.com/chrome/tools/build.git'
  c.got_revision_mapping['build_internal'] = 'got_revision'
  # We do not use 'includes' here, because we want build_internal to be the
  # first solution in the list as run_presubmit computes upstream revision
  # from the first solution.
  build(c)
  c.got_revision_mapping['build'] = 'got_build_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def build_internal_scripts_slave(c):
  if not c.GIT_MODE:  # pragma: no cover
    raise BadConf('build_internal_scripts_slave only supports git')
  s = c.solutions.add()
  s.name = 'build_internal/scripts/slave'
  s.url = ('https://chrome-internal.googlesource.com/'
           'chrome/tools/build_limited/scripts/slave.git')
  c.got_revision_mapping['build_internal/scripts/slave'] = 'got_revision'
  # We do not use 'includes' here, because we want build_internal to be the
  # first solution in the list as run_presubmit computes upstream revision
  # from the first solution.
  build(c)
  c.got_revision_mapping['build'] = 'got_build_revision'

@config_ctx()
def master_deps(c):
  s = c.solutions.add()
  s.name = 'build_internal/master.DEPS'
  s.url = ('https://chrome-internal.googlesource.com/'
           'chrome/tools/build/master.DEPS.git')
  c.got_revision_mapping['build_internal/master.DEPS'] = 'got_revision'

@config_ctx()
def slave_deps(c):
  s = c.solutions.add()
  s.name = 'build_internal/slave.DEPS'
  s.url = ('https://chrome-internal.googlesource.com/'
           'chrome/tools/build/slave.DEPS.git')
  c.got_revision_mapping['build_internal/slave.DEPS'] = 'got_revision'

@config_ctx()
def internal_deps(c):
  s = c.solutions.add()
  s.name = 'build_internal/internal.DEPS'
  s.url = ('https://chrome-internal.googlesource.com/'
           'chrome/tools/build/internal.DEPS.git')
  c.got_revision_mapping['build_internal/internal.DEPS'] = 'got_revision'

@config_ctx(includes=['chromium', 'chrome_internal'])
def perf(c):
  s = c.solutions[0]
  s.custom_vars['llvm_url'] = 'svn://svn-mirror.golo.chromium.org/llvm-project'
  s.managed = False
  needed_components_internal = [
    "src/data/page_cycler",
  ]
  for key in needed_components_internal:
    del c.solutions[1].custom_deps[key]
  c.solutions[1].managed = False

@config_ctx(includes=['chromium'])
def chromium_skia(c):
  c.solutions[0].revision = 'HEAD'
  del c.solutions[0].custom_deps
  c.revisions['src/third_party/skia'] = (
      gclient_api.RevisionFallbackChain('origin/master'))
  c.got_revision_mapping['src'] = 'got_chromium_revision'
  c.got_revision_mapping['src/third_party/skia'] = 'got_revision'
  c.parent_got_revision_mapping['parent_got_revision'] = 'got_revision'

@config_ctx(includes=['chromium'])
def chromium_webrtc(c):
  c.got_revision_mapping['src/third_party/libjingle/source/talk'] = (
      'got_libjingle_revision')
  c.got_revision_mapping['src/third_party/libvpx/source'] = (
      'got_libvpx_revision')

@config_ctx(includes=['chromium_webrtc'])
def chromium_webrtc_tot(c):
  """Configures ToT revisions for WebRTC and Libjingle for Chromium.

  Sets up ToT instead of the DEPS-pinned revision for WebRTC and Libjingle.
  This is used for some bots to provide data about which revisions are green to
  roll into Chromium.
  """
  c.revisions['src'] = 'HEAD'
  c.revisions['src/third_party/webrtc'] = 'HEAD'
  c.revisions['src/third_party/libjingle/source/talk'] = 'HEAD'

@config_ctx()
def webrtc_test_resources(c):
  """Add webrtc.DEPS solution for test resources and tools.

  The webrtc.DEPS solution pulls in additional resources needed for running
  WebRTC-specific test setups in Chromium.
  """
  s = c.solutions.add()
  s.name = 'webrtc.DEPS'
  s.url = ChromiumGitURL(c, 'chromium', 'deps', 'webrtc', 'webrtc.DEPS')
  s.deps_file = 'DEPS'

@config_ctx()
def pdfium(c):
  soln = c.solutions.add()
  soln.name = 'pdfium'
  soln.url = 'https://pdfium.googlesource.com/pdfium.git'

@config_ctx()
def mojo(c):
  soln = c.solutions.add()
  soln.name = 'src'
  soln.url = 'https://chromium.googlesource.com/external/mojo.git'

@config_ctx()
def crashpad(c):
  soln = c.solutions.add()
  soln.name = 'crashpad'
  soln.url = 'https://chromium.googlesource.com/crashpad/crashpad.git'

@config_ctx()
def boringssl(c):
  soln = c.solutions.add()
  soln.name = 'boringssl'
  soln.url = 'https://boringssl.googlesource.com/boringssl.git'
  soln.deps_file = 'util/bot/DEPS'

@config_ctx()
def dart(c):
  soln = c.solutions.add()
  soln.name = 'sdk'
  soln.url = ('https://chromium.googlesource.com/external/github.com/' +
              'dart-lang/sdk.git')
  soln.deps_file = 'DEPS'
  soln.managed = False

@config_ctx(config_vars={'GIT_MODE': True})
def infra(c):
  soln = c.solutions.add()
  soln.name = 'infra'
  soln.url = 'https://chromium.googlesource.com/infra/infra.git'
  c.got_revision_mapping['infra'] = 'got_revision'

@config_ctx(config_vars={'GIT_MODE': True})
def infra_internal(c):  # pragma: no cover
  soln = c.solutions.add()
  soln.name = 'infra_internal'
  soln.url = 'https://chrome-internal.googlesource.com/infra/infra_internal.git'
  c.got_revision_mapping['infra_internal'] = 'got_revision'

@config_ctx(includes=['infra'])
def luci_gae(c):
  # luci/gae is checked out as a part of infra.git solution at HEAD.
  c.revisions['infra'] = 'origin/master'
  # luci/gae is developed together with luci-go, which should be at HEAD.
  c.revisions['infra/go/src/github.com/luci/luci-go'] = 'origin/master'
  c.revisions['infra/go/src/github.com/luci/gae'] = (
      gclient_api.RevisionFallbackChain('origin/master'))
  m = c.got_revision_mapping
  del m['infra']
  m['infra/go/src/github.com/luci/gae'] = 'got_revision'

@config_ctx(includes=['infra'])
def luci_go(c):
  # luci-go is checked out as a part of infra.git solution at HEAD.
  c.revisions['infra'] = 'origin/master'
  c.revisions['infra/go/src/github.com/luci/luci-go'] = (
      gclient_api.RevisionFallbackChain('origin/master'))
  m = c.got_revision_mapping
  del m['infra']
  m['infra/go/src/github.com/luci/luci-go'] = 'got_revision'

@config_ctx(includes=['infra'])
def luci_py(c):
  # luci-py is checked out as part of infra just to have appengine
  # pre-installed, as that's what luci-py PRESUBMIT relies on.
  c.revisions['infra'] = 'origin/master'
  c.revisions['infra/luci'] = (
      gclient_api.RevisionFallbackChain('origin/master'))
  m = c.got_revision_mapping
  del m['infra']
  m['infra/luci'] = 'got_revision'

@config_ctx(includes=['infra'])
def recipes_py(c):
  c.revisions['infra'] = 'origin/master'
  c.revisions['infra/recipes-py'] = (
      gclient_api.RevisionFallbackChain('origin/master'))
  m = c.got_revision_mapping
  del m['infra']
  m['infra/recipes-py'] = 'got_revision'

@config_ctx()
def chrome_from_buildspec(c):  # pragma: no cover
  soln = c.solutions.add()
  soln.name = 'chrome_from_buildspec'
  # This URL has to be augmented with the appropriate bucket by the recipe using
  # it.
  soln.url = ('svn://svn-mirror.golo.chromium.org/chrome-internal/trunk/tools/'
      'buildspec/build/')
  soln.custom_vars['svn_url'] = 'svn://svn-mirror.golo.chromium.org'
  soln.custom_deps = {}

@config_ctx()
def catapult(c):
  soln = c.solutions.add()
  soln.name = 'catapult'
  soln.url = ('https://chromium.googlesource.com/external/github.com/'
              'catapult-project/catapult.git')
  c.got_revision_mapping['catapult'] = 'got_revision'

@config_ctx(includes=['infra_internal'], config_vars={'GIT_MODE': True})
def infradata_master_manager(c):
  soln = c.solutions.add()
  soln.name = 'infra-data-master-manager'
  soln.url = (
      'https://chrome-internal.googlesource.com/infradata/master-manager.git')
  c.got_revision_mapping['infra-data-master-manager'] = 'got_revision'

@config_ctx()
def with_branch_heads(c):
  c.with_branch_heads = True

@config_ctx()
def custom_tabs_client(c):
  soln = c.solutions.add()
  soln.name = 'custom_tabs_client'
  # TODO(pasko): test custom-tabs-client within a full chromium checkout.
  soln.url = ('https://chromium.googlesource.com/external/github.com/'
              'GoogleChrome/custom-tabs-client.git')
  c.got_revision_mapping['custom_tabs_client'] = 'got_revision'

# TODO(phajdan.jr): Move to proper repo and add coverage.
@config_ctx()
def angle_top_of_tree(c):  # pragma: no cover
  """Configures the top-of-tree ANGLE in a Chromium checkout.

  Sets up ToT instead of the DEPS-pinned revision for ANGLE.
  """
  c.solutions[0].revision = 'HEAD'
  c.revisions['src/third_party/angle'] = 'HEAD'

@config_ctx()
def gerrit_test_cq_normal(c):
  soln = c.solutions.add()
  soln.name = 'gerrit-test-cq-normal'
  soln.url = 'https://chromium.googlesource.com/playground/gerrit-cq/normal.git'

# TODO(phajdan.jr): Move to proper repo and add coverage.
@config_ctx()
def valgrind(c):  # pragma: no cover
  """Add Valgrind binaries to the gclient solution."""
  c.solutions[0].custom_deps['src/third_party/valgrind'] = \
    ChromiumGitURL(c, 'chromium', 'deps', 'valgrind', 'binaries')
