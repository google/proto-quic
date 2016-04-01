# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from recipe_engine import recipe_api


class RevisionResolver(object):
  """Resolves the revision based on build properties."""

  def resolve(self, properties):  # pragma: no cover
    raise NotImplementedError()


class RevisionFallbackChain(RevisionResolver):
  """Specify that a given project's sync revision follows the fallback chain."""
  def __init__(self, default=None):
    self._default = default

  def resolve(self, properties):
    """Resolve the revision via the revision fallback chain.

    If the given revision was set using the revision_fallback_chain() function,
    this function will follow the chain, looking at relevant build properties
    until it finds one set or reaches the end of the chain and returns the
    default. If the given revision was not set using revision_fallback_chain(),
    this function just returns it as-is.
    """
    return (properties.get('parent_got_revision') or
            properties.get('orig_revision') or
            properties.get('revision') or
            self._default)


class ProjectRevisionResolver(RevisionResolver):
  """Revision resolver that takes into account the project."""
  def __init__(self, project, parent_got_revision=None):
    self.project = project
    self.parent_got_revision = parent_got_revision or 'parent_got_revision'

  # TODO(phajdan.jr): Move to proper repo and add coverage.
  def resolve(self, properties):  # pragma: no cover
    """Resolve the revision if project matches, otherwise default to HEAD."""
    if properties.get('project') == self.project:
      return (properties.get(self.parent_got_revision) or
              properties.get('revision') or
              'HEAD')
    return (properties.get(self.parent_got_revision) or
            'HEAD')


def jsonish_to_python(spec, is_top=False):
  ret = ''
  if is_top:  # We're the 'top' level, so treat this dict as a suite.
    ret = '\n'.join(
      '%s = %s' % (k, jsonish_to_python(spec[k])) for k in sorted(spec)
    )
  else:
    if isinstance(spec, dict):
      ret += '{'
      ret += ', '.join(
        "%s: %s" % (repr(str(k)), jsonish_to_python(spec[k]))
        for k in sorted(spec)
      )
      ret += '}'
    elif isinstance(spec, list):
      ret += '['
      ret += ', '.join(jsonish_to_python(x) for x in spec)
      ret += ']'
    elif isinstance(spec, basestring):
      ret = repr(str(spec))
    else:
      ret = repr(spec)
  return ret

class GclientApi(recipe_api.RecipeApi):
  # Singleton object to indicate to checkout() that we should run a revert if
  # we detect that we're on the tryserver.
  RevertOnTryserver = object()

  def __init__(self, **kwargs):
    super(GclientApi, self).__init__(**kwargs)
    self.USE_MIRROR = None
    self._spec_alias = None

  def __call__(self, name, cmd, infra_step=True, **kwargs):
    """Wrapper for easy calling of gclient steps."""
    assert isinstance(cmd, (list, tuple))
    prefix = 'gclient '
    if self.spec_alias:
      prefix = ('[spec: %s] ' % self.spec_alias) + prefix

    kwargs.setdefault('env', {})
    kwargs['env'].setdefault('PATH', '%(PATH)s')
    kwargs['env']['PATH'] = self.m.path.pathsep.join([
        kwargs['env']['PATH'], str(self._module.PACKAGE_DIRECTORY)])

    return self.m.python(prefix + name,
                         self.package_resource('gclient.py'),
                         cmd,
                         infra_step=infra_step,
                         **kwargs)

  @property
  def use_mirror(self):
    """Indicates if gclient will use mirrors in its configuration."""
    if self.USE_MIRROR is None:
      self.USE_MIRROR = self.m.properties.get('use_mirror', True)
    return self.USE_MIRROR

  @use_mirror.setter
  def use_mirror(self, val):  # pragma: no cover
    self.USE_MIRROR = val

  @property
  def spec_alias(self):
    """Optional name for the current spec for step naming."""
    return self._spec_alias

  @spec_alias.setter
  def spec_alias(self, name):
    self._spec_alias = name

  @spec_alias.deleter
  def spec_alias(self):
    self._spec_alias = None

  def get_config_defaults(self):
    ret = {
      'USE_MIRROR': self.use_mirror
    }
    ret['CACHE_DIR'] = self.m.path['root'].join('git_cache')
    return ret

  def resolve_revision(self, revision):
    if hasattr(revision, 'resolve'):
      return revision.resolve(self.m.properties)
    return revision

  def sync(self, cfg, with_branch_heads=False, **kwargs):
    revisions = []
    for i, s in enumerate(cfg.solutions):
      if s.safesync_url:  # prefer safesync_url in gclient mode
        continue
      if i == 0 and s.revision is None:
        s.revision = RevisionFallbackChain()

      if s.revision is not None and s.revision != '':
        fixed_revision = self.resolve_revision(s.revision)
        if fixed_revision:
          revisions.extend(['--revision', '%s@%s' % (s.name, fixed_revision)])

    for name, revision in sorted(cfg.revisions.items()):
      fixed_revision = self.resolve_revision(revision)
      if fixed_revision:
        revisions.extend(['--revision', '%s@%s' % (name, fixed_revision)])

    test_data_paths = set(cfg.got_revision_mapping.keys() +
                          [s.name for s in cfg.solutions])
    step_test_data = lambda: (
      self.test_api.output_json(test_data_paths, cfg.GIT_MODE))
    try:
      if not cfg.GIT_MODE:
        args = ['sync', '--nohooks', '--force', '--verbose']
        if cfg.delete_unversioned_trees:
          args.append('--delete_unversioned_trees')
        if with_branch_heads:
          args.append('--with_branch_heads')
        self('sync', args + revisions + ['--output-json', self.m.json.output()],
                   step_test_data=step_test_data,
                   **kwargs)
      else:
        # clean() isn't used because the gclient sync flags passed in checkout()
        # do much the same thing, and they're more correct than doing a separate
        # 'gclient revert' because it makes sure the other args are correct when
        # a repo was deleted and needs to be re-cloned (notably
        # --with_branch_heads), whereas 'revert' uses default args for clone
        # operations.
        #
        # TODO(mmoss): To be like current official builders, this step could
        # just delete the whole <slave_name>/build/ directory and start each
        # build from scratch. That might be the least bad solution, at least
        # until we have a reliable gclient method to produce a pristine working
        # dir for git-based builds (e.g. maybe some combination of 'git
        # reset/clean -fx' and removing the 'out' directory).
        j = '-j2' if self.m.platform.is_win else '-j8'
        args = ['sync', '--verbose', '--with_branch_heads', '--nohooks', j,
                '--reset', '--force', '--upstream', '--no-nag-max']
        if cfg.delete_unversioned_trees:
          args.append('--delete_unversioned_trees')
        self('sync', args + revisions +
                   ['--output-json', self.m.json.output()],
                   step_test_data=step_test_data,
                   **kwargs)
    finally:
      result = self.m.step.active_result
      data = result.json.output
      for path, info in data['solutions'].iteritems():
        # gclient json paths always end with a slash
        path = path.rstrip('/')
        if path in cfg.got_revision_mapping:
          propname = cfg.got_revision_mapping[path]
          result.presentation.properties[propname] = info['revision']

    return result

  def inject_parent_got_revision(self, gclient_config=None, override=False):
    """Match gclient config to build revisions obtained from build_properties.

    Args:
      gclient_config (gclient config object) - The config to manipulate. A value
        of None manipulates the module's built-in config (self.c).
      override (bool) - If True, will forcibly set revision and custom_vars
        even if the config already contains values for them.
    """
    cfg = gclient_config or self.c

    for prop, custom_var in cfg.parent_got_revision_mapping.iteritems():
      val = str(self.m.properties.get(prop, ''))
      # TODO(infra): Fix coverage.
      if val:  # pragma: no cover
        # Special case for 'src', inject into solutions[0]
        if custom_var is None:
          # This is not covered because we are deprecating this feature and
          # it is no longer used by the public recipes.
          if cfg.solutions[0].revision is None or override:  # pragma: no cover
            cfg.solutions[0].revision = val
        else:
          if custom_var not in cfg.solutions[0].custom_vars or override:
            cfg.solutions[0].custom_vars[custom_var] = val

  def checkout(self, gclient_config=None, revert=RevertOnTryserver,
               inject_parent_got_revision=True, with_branch_heads=False,
               **kwargs):
    """Return a step generator function for gclient checkouts."""
    cfg = gclient_config or self.c
    assert cfg.complete()

    if revert is self.RevertOnTryserver:
      revert = self.m.tryserver.is_tryserver

    if inject_parent_got_revision:
      self.inject_parent_got_revision(cfg, override=True)

    spec_string = jsonish_to_python(cfg.as_jsonish(), True)

    self('setup', ['config', '--spec', spec_string], **kwargs)

    sync_step = None
    try:
      if not cfg.GIT_MODE:
        try:
          if revert:
            self.revert(**kwargs)
        finally:
          sync_step = self.sync(cfg, with_branch_heads=with_branch_heads,
                                **kwargs)
      else:
        sync_step = self.sync(cfg, with_branch_heads=with_branch_heads,
                              **kwargs)

        cfg_cmds = [
          ('user.name', 'local_bot'),
          ('user.email', 'local_bot@example.com'),
        ]
        for var, val in cfg_cmds:
          name = 'recurse (git config %s)' % var
          self(name, ['recurse', 'git', 'config', var, val], **kwargs)

    finally:
      cwd = kwargs.get('cwd', self.m.path['slave_build'])
      if 'checkout' not in self.m.path:
        self.m.path['checkout'] = cwd.join(
          *cfg.solutions[0].name.split(self.m.path.sep))

    return sync_step

  def revert(self, **kwargs):
    """Return a gclient_safe_revert step."""
    # Not directly calling gclient, so don't use self().
    alias = self.spec_alias
    prefix = '%sgclient ' % (('[spec: %s] ' % alias) if alias else '')

    return self.m.python(prefix + 'revert',
        self.m.path['build'].join('scripts', 'slave', 'gclient_safe_revert.py'),
        ['.', self.m.path['depot_tools'].join('gclient',
                                              platform_ext={'win': '.bat'})],
        infra_step=True,
        **kwargs
    )

  def runhooks(self, args=None, name='runhooks', **kwargs):
    args = args or []
    assert isinstance(args, (list, tuple))
    return self(
      name, ['runhooks'] + list(args), infra_step=False, **kwargs)

  @property
  def is_blink_mode(self):
    """ Indicates wether the caller is to use the Blink config rather than the
    Chromium config. This may happen for one of two reasons:
    1. The builder is configured to always use TOT Blink. (factory property
       top_of_tree_blink=True)
    2. A try job comes in that applies to the Blink tree. (patch_project is
       blink)
    """
    return (
      self.m.properties.get('top_of_tree_blink') or
      self.m.properties.get('patch_project') == 'blink')

  def break_locks(self):
    """Remove all index.lock files. If a previous run of git crashed, bot was
    reset, etc... we might end up with leftover index.lock files.
    """
    self.m.python.inline(
      'cleanup index.lock',
      """
        import os, sys

        build_path = sys.argv[1]
        if os.path.exists(build_path):
          for (path, dir, files) in os.walk(build_path):
            for cur_file in files:
              if cur_file.endswith('index.lock'):
                path_to_file = os.path.join(path, cur_file)
                print 'deleting %s' % path_to_file
                os.remove(path_to_file)
      """,
      args=[self.m.path['slave_build']],
      infra_step=True,
    )
