#!/usr/bin/env python
#
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import os
import shutil
import re
import sys
import textwrap

from util import build_utils
from util import md5_check

import jar

sys.path.append(build_utils.COLORAMA_ROOT)
import colorama


def ColorJavacOutput(output):
  fileline_prefix = r'(?P<fileline>(?P<file>[-.\w/\\]+.java):(?P<line>[0-9]+):)'
  warning_re = re.compile(
      fileline_prefix + r'(?P<full_message> warning: (?P<message>.*))$')
  error_re = re.compile(
      fileline_prefix + r'(?P<full_message> (?P<message>.*))$')
  marker_re = re.compile(r'\s*(?P<marker>\^)\s*$')

  warning_color = ['full_message', colorama.Fore.YELLOW + colorama.Style.DIM]
  error_color = ['full_message', colorama.Fore.MAGENTA + colorama.Style.BRIGHT]
  marker_color = ['marker',  colorama.Fore.BLUE + colorama.Style.BRIGHT]

  def Colorize(line, regex, color):
    match = regex.match(line)
    start = match.start(color[0])
    end = match.end(color[0])
    return (line[:start]
            + color[1] + line[start:end]
            + colorama.Fore.RESET + colorama.Style.RESET_ALL
            + line[end:])

  def ApplyColor(line):
    if warning_re.match(line):
      line = Colorize(line, warning_re, warning_color)
    elif error_re.match(line):
      line = Colorize(line, error_re, error_color)
    elif marker_re.match(line):
      line = Colorize(line, marker_re, marker_color)
    return line

  return '\n'.join(map(ApplyColor, output.split('\n')))


ERRORPRONE_OPTIONS = [
  # These crash on lots of targets.
  '-Xep:ParameterPackage:OFF',
  '-Xep:OverridesGuiceInjectableMethod:OFF',
  '-Xep:OverridesJavaxInjectableMethod:OFF',
]


def _FilterJavaFiles(paths, filters):
  return [f for f in paths
          if not filters or build_utils.MatchesGlob(f, filters)]


_MAX_MANIFEST_LINE_LEN = 72


def _CreateManifest(manifest_path, classpath, main_class=None,
                    manifest_entries=None):
  """Creates a manifest file with the given parameters.

  This generates a manifest file that compiles with the spec found at
  http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#JAR_Manifest

  Args:
    manifest_path: The path to the manifest file that should be created.
    classpath: The JAR files that should be listed on the manifest file's
      classpath.
    main_class: If present, the class containing the main() function.
    manifest_entries: If present, a list of (key, value) pairs to add to
      the manifest.

  """
  output = ['Manifest-Version: 1.0']
  if main_class:
    output.append('Main-Class: %s' % main_class)
  if manifest_entries:
    for k, v in manifest_entries:
      output.append('%s: %s' % (k, v))
  if classpath:
    sanitized_paths = []
    for path in classpath:
      sanitized_paths.append(os.path.basename(path.strip('"')))
    output.append('Class-Path: %s' % ' '.join(sanitized_paths))
  output.append('Created-By: ')
  output.append('')

  wrapper = textwrap.TextWrapper(break_long_words=True,
                                 drop_whitespace=False,
                                 subsequent_indent=' ',
                                 width=_MAX_MANIFEST_LINE_LEN - 2)
  output = '\r\n'.join(w for l in output for w in wrapper.wrap(l))

  with open(manifest_path, 'w') as f:
    f.write(output)


def _ExtractClassFiles(jar_path, dest_dir, java_files):
  """Extracts all .class files not corresponding to |java_files|."""
  # Two challenges exist here:
  # 1. |java_files| have prefixes that are not represented in the the jar paths.
  # 2. A single .java file results in multiple .class files when it contains
  #    nested classes.
  # Here's an example:
  #   source path: ../../base/android/java/src/org/chromium/Foo.java
  #   jar paths: org/chromium/Foo.class, org/chromium/Foo$Inner.class
  # To extract only .class files not related to the given .java files, we strip
  # off ".class" and "$*.class" and use a substring match against java_files.
  def extract_predicate(path):
    if not path.endswith('.class'):
      return False
    path_without_suffix = re.sub(r'(?:\$|\.)[^/]+class$', '', path)
    partial_java_path = path_without_suffix + '.java'
    return not any(p.endswith(partial_java_path) for p in java_files)

  build_utils.ExtractAll(jar_path, path=dest_dir, predicate=extract_predicate)
  for path in build_utils.FindInDirectory(dest_dir, '*.class'):
    shutil.copystat(jar_path, path)


def _ConvertToJMakeArgs(javac_cmd, pdb_path):
  new_args = ['bin/jmake', '-pdb', pdb_path]
  if javac_cmd[0] != 'javac':
    new_args.extend(('-jcexec', new_args[0]))
  if md5_check.PRINT_EXPLANATIONS:
    new_args.append('-Xtiming')

  do_not_prefix = ('-classpath', '-bootclasspath')
  skip_next = False
  for arg in javac_cmd[1:]:
    if not skip_next and arg not in do_not_prefix:
      arg = '-C' + arg
    new_args.append(arg)
    skip_next = arg in do_not_prefix

  return new_args


def _FixTempPathsInIncrementalMetadata(pdb_path, temp_dir):
  # The .pdb records absolute paths. Fix up paths within /tmp (srcjars).
  if os.path.exists(pdb_path):
    # Although its a binary file, search/replace still seems to work fine.
    with open(pdb_path) as fileobj:
      pdb_data = fileobj.read()
    with open(pdb_path, 'w') as fileobj:
      fileobj.write(re.sub(r'/tmp/[^/]*', temp_dir, pdb_data))


def _OnStaleMd5(changes, options, javac_cmd, java_files, classpath_inputs,
                runtime_classpath):
  with build_utils.TempDir() as temp_dir:
    srcjars = options.java_srcjars
    # The .excluded.jar contains .class files excluded from the main jar.
    # It is used for incremental compiles.
    excluded_jar_path = options.jar_path.replace('.jar', '.excluded.jar')

    classes_dir = os.path.join(temp_dir, 'classes')
    os.makedirs(classes_dir)

    changed_paths = None
    # jmake can handle deleted files, but it's a rare case and it would
    # complicate this script's logic.
    if options.incremental and changes.AddedOrModifiedOnly():
      changed_paths = set(changes.IterChangedPaths())
      # Do a full compile if classpath has changed.
      # jmake doesn't seem to do this on its own... Might be that ijars mess up
      # its change-detection logic.
      if any(p in changed_paths for p in classpath_inputs):
        changed_paths = None

    if options.incremental:
      # jmake is a compiler wrapper that figures out the minimal set of .java
      # files that need to be rebuilt given a set of .java files that have
      # changed.
      # jmake determines what files are stale based on timestamps between .java
      # and .class files. Since we use .jars, .srcjars, and md5 checks,
      # timestamp info isn't accurate for this purpose. Rather than use jmake's
      # programatic interface (like we eventually should), we ensure that all
      # .class files are newer than their .java files, and convey to jmake which
      # sources are stale by having their .class files be missing entirely
      # (by not extracting them).
      pdb_path = options.jar_path + '.pdb'
      javac_cmd = _ConvertToJMakeArgs(javac_cmd, pdb_path)
      if srcjars:
        _FixTempPathsInIncrementalMetadata(pdb_path, temp_dir)

    if srcjars:
      java_dir = os.path.join(temp_dir, 'java')
      os.makedirs(java_dir)
      for srcjar in options.java_srcjars:
        if changed_paths:
          changed_paths.update(os.path.join(java_dir, f)
                               for f in changes.IterChangedSubpaths(srcjar))
        build_utils.ExtractAll(srcjar, path=java_dir, pattern='*.java')
      jar_srcs = build_utils.FindInDirectory(java_dir, '*.java')
      jar_srcs = _FilterJavaFiles(jar_srcs, options.javac_includes)
      java_files.extend(jar_srcs)
      if changed_paths:
        # Set the mtime of all sources to 0 since we use the absense of .class
        # files to tell jmake which files are stale.
        for path in jar_srcs:
          os.utime(path, (0, 0))

    if java_files:
      if changed_paths:
        changed_java_files = [p for p in java_files if p in changed_paths]
        if os.path.exists(options.jar_path):
          _ExtractClassFiles(options.jar_path, classes_dir, changed_java_files)
        if os.path.exists(excluded_jar_path):
          _ExtractClassFiles(excluded_jar_path, classes_dir, changed_java_files)
        # Add the extracted files to the classpath. This is required because
        # when compiling only a subset of files, classes that haven't changed
        # need to be findable.
        classpath_idx = javac_cmd.index('-classpath')
        javac_cmd[classpath_idx + 1] += ':' + classes_dir

      # Can happen when a target goes from having no sources, to having sources.
      # It's created by the call to build_utils.Touch() below.
      if options.incremental:
        if os.path.exists(pdb_path) and not os.path.getsize(pdb_path):
          os.unlink(pdb_path)

      # Don't include the output directory in the initial set of args since it
      # being in a temp dir makes it unstable (breaks md5 stamping).
      cmd = javac_cmd + ['-d', classes_dir] + java_files

      # JMake prints out some diagnostic logs that we want to ignore.
      # This assumes that all compiler output goes through stderr.
      stdout_filter = lambda s: ''
      if md5_check.PRINT_EXPLANATIONS:
        stdout_filter = None

      attempt_build = lambda: build_utils.CheckOutput(
          cmd,
          print_stdout=options.chromium_code,
          stdout_filter=stdout_filter,
          stderr_filter=ColorJavacOutput)
      try:
        attempt_build()
      except build_utils.CalledProcessError as e:
        # Work-around for a bug in jmake (http://crbug.com/551449).
        if 'project database corrupted' not in e.output:
          raise
        print ('Applying work-around for jmake project database corrupted '
               '(http://crbug.com/551449).')
        os.unlink(pdb_path)
        attempt_build()
    elif options.incremental:
      # Make sure output exists.
      build_utils.Touch(pdb_path)

    if options.main_class or options.manifest_entry:
      entries = []
      if options.manifest_entry:
        entries = [e.split(':') for e in options.manifest_entry]
      manifest_file = os.path.join(temp_dir, 'manifest')
      _CreateManifest(manifest_file, runtime_classpath, options.main_class,
                      entries)
    else:
      manifest_file = None

    glob = options.jar_excluded_classes
    inclusion_predicate = lambda f: not build_utils.MatchesGlob(f, glob)
    exclusion_predicate = lambda f: not inclusion_predicate(f)

    jar.JarDirectory(classes_dir,
                     options.jar_path,
                     manifest_file=manifest_file,
                     predicate=inclusion_predicate)
    jar.JarDirectory(classes_dir,
                     excluded_jar_path,
                     predicate=exclusion_predicate)


def _ParseOptions(argv):
  parser = optparse.OptionParser()
  build_utils.AddDepfileOption(parser)

  parser.add_option(
      '--src-gendirs',
      help='Directories containing generated java files.')
  parser.add_option(
      '--java-srcjars',
      action='append',
      default=[],
      help='List of srcjars to include in compilation.')
  parser.add_option(
      '--bootclasspath',
      action='append',
      default=[],
      help='Boot classpath for javac. If this is specified multiple times, '
      'they will all be appended to construct the classpath.')
  parser.add_option(
      '--classpath',
      action='append',
      help='Classpath for javac. If this is specified multiple times, they '
      'will all be appended to construct the classpath.')
  parser.add_option(
      '--use-ijars',
      action='store_true',
      help='Whether to use interface jars (.interface.jar) when compiling')
  parser.add_option(
      '--incremental',
      action='store_true',
      help='Whether to re-use .class files rather than recompiling them '
           '(when possible).')
  parser.add_option(
      '--javac-includes',
      default='',
      help='A list of file patterns. If provided, only java files that match'
      'one of the patterns will be compiled.')
  parser.add_option(
      '--jar-excluded-classes',
      default='',
      help='List of .class file patterns to exclude from the jar.')

  parser.add_option(
      '--chromium-code',
      type='int',
      help='Whether code being compiled should be built with stricter '
      'warnings for chromium code.')

  parser.add_option(
      '--use-errorprone-path',
      help='Use the Errorprone compiler at this path.')

  parser.add_option('--jar-path', help='Jar output path.')
  parser.add_option(
      '--main-class',
      help='The class containing the main method.')
  parser.add_option(
      '--manifest-entry',
      action='append',
      help='Key:value pairs to add to the .jar manifest.')

  parser.add_option('--stamp', help='Path to touch on success.')

  options, args = parser.parse_args(argv)
  build_utils.CheckOptions(options, parser, required=('jar_path',))

  bootclasspath = []
  for arg in options.bootclasspath:
    bootclasspath += build_utils.ParseGypList(arg)
  options.bootclasspath = bootclasspath

  classpath = []
  for arg in options.classpath:
    classpath += build_utils.ParseGypList(arg)
  options.classpath = classpath

  java_srcjars = []
  for arg in options.java_srcjars:
    java_srcjars += build_utils.ParseGypList(arg)
  options.java_srcjars = java_srcjars

  if options.src_gendirs:
    options.src_gendirs = build_utils.ParseGypList(options.src_gendirs)

  options.javac_includes = build_utils.ParseGypList(options.javac_includes)
  options.jar_excluded_classes = (
      build_utils.ParseGypList(options.jar_excluded_classes))
  return options, args


def main(argv):
  colorama.init()

  argv = build_utils.ExpandFileArgs(argv)
  options, java_files = _ParseOptions(argv)

  if options.src_gendirs:
    java_files += build_utils.FindInDirectories(options.src_gendirs, '*.java')

  java_files = _FilterJavaFiles(java_files, options.javac_includes)

  runtime_classpath = options.classpath
  compile_classpath = runtime_classpath
  if options.use_ijars:
    ijar_re = re.compile(r'\.jar$')
    compile_classpath = (
        [ijar_re.sub('.interface.jar', p) for p in runtime_classpath])

  javac_cmd = ['javac']
  if options.use_errorprone_path:
    javac_cmd = [options.use_errorprone_path] + ERRORPRONE_OPTIONS

  javac_cmd.extend((
      '-g',
      # Chromium only allows UTF8 source files.  Being explicit avoids
      # javac pulling a default encoding from the user's environment.
      '-encoding', 'UTF-8',
      '-classpath', ':'.join(compile_classpath),
      # Prevent compiler from compiling .java files not listed as inputs.
      # See: http://blog.ltgt.net/most-build-tools-misuse-javac/
      '-sourcepath', ''
  ))

  if options.bootclasspath:
    javac_cmd.extend([
        '-bootclasspath', ':'.join(options.bootclasspath),
        '-source', '1.7',
        '-target', '1.7',
        ])

  if options.chromium_code:
    javac_cmd.extend(['-Xlint:unchecked', '-Xlint:deprecation'])
  else:
    # XDignore.symbol.file makes javac compile against rt.jar instead of
    # ct.sym. This means that using a java internal package/class will not
    # trigger a compile warning or error.
    javac_cmd.extend(['-XDignore.symbol.file'])

  classpath_inputs = options.bootclasspath
  # TODO(agrieve): Remove this .TOC heuristic once GYP is no more.
  if options.use_ijars:
    classpath_inputs.extend(compile_classpath)
  else:
    for path in compile_classpath:
      if os.path.exists(path + '.TOC'):
        classpath_inputs.append(path + '.TOC')
      else:
        classpath_inputs.append(path)

  # Compute the list of paths that when changed, we need to rebuild.
  input_paths = classpath_inputs + options.java_srcjars + java_files

  output_paths = [
      options.jar_path,
      options.jar_path.replace('.jar', '.excluded.jar'),
  ]
  if options.incremental:
    output_paths.append(options.jar_path + '.pdb')

  # An escape hatch to be able to check if incremental compiles are causing
  # problems.
  force = int(os.environ.get('DISABLE_INCREMENTAL_JAVAC', 0))

  # List python deps in input_strings rather than input_paths since the contents
  # of them does not change what gets written to the depsfile.
  build_utils.CallAndWriteDepfileIfStale(
      lambda changes: _OnStaleMd5(changes, options, javac_cmd, java_files,
                                  classpath_inputs, runtime_classpath),
      options,
      input_paths=input_paths,
      input_strings=javac_cmd,
      output_paths=output_paths,
      force=force,
      pass_changes=True)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
