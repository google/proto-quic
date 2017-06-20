#!/usr/bin/env python

# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import os.path
import shutil
import subprocess
import sys
import tempfile

# How to patch libxml2 in Chromium:
#
# 1. Write a .patch file and add it to third_party/libxml/chromium.
# 2. Apply the patch in src: patch -p1 <../chromium/foo.patch
# 3. Add the patch to the list of patches in this file.
# 4. Update README.chromium with the provenance of the patch.
# 5. Upload a change with the modified documentation, roll script,
#    patch, applied patch and any other relevant changes like
#    regression tests. Go through the usual review and commit process.
#
# How to roll libxml2 in Chromium:
#
# Prerequisites:
#
# 1. Check out Chromium somewhere on Linux, Mac and Windows.
# 2. On each machine, add the experimental remote named 'wip':
#    git remote add -f wip \
#        https://chromium.googlesource.com/experimental/chromium/src
# 3. On Linux:
#    a. sudo apt-get install libicu-dev
#    b. git clone git://git.gnome.org/libxml2 somewhere
# 4. On Mac, install these MacPorts:
#    autoconf automake libtool pkgconfig icu
#
# Procedure:
#
# Warning: This process is destructive. Run it on a clean branch.
#
# 1. On Linux, in the libxml2 repo directory:
#    a. git remote update origin
#    b. git checkout origin/master
#
#    This will be the upstream version of libxml you are rolling to.
#
# 2. On Linux, in the Chromium src director:
#    a. third_party/libxml/chromium/roll.py --linux /path/to/libxml2
#
#    If this fails, it may be a patch no longer applies. Reset to
#    head; modify the patch files, this script, and
#    README.chromium; then commit the result and run it again.
#
#    b. git push -f wip HEAD:refs/wip/$USER/roll_libxml
#
# 2. On Windows, in the Chromium src directory:
#    a. git fetch wip refs/wip/$USER/roll_libxml
#    b. git checkout FETCH_HEAD
#    c. third_party\libxml\chromium\roll.py --win32
#    d. git push -f wip HEAD:refs/wip/$USER/roll_libxml
#
# 3. On Mac, in the Chromium src directory:
#    a. git fetch wip refs/wip/$USER/roll_libxml
#    b. git checkout -b roll_libxml_nnnn FETCH_HEAD
#    c. git branch --set-upstream-to origin/master
#    d. third_party/libxml/chromium/roll.py --mac
#    e. Make and commit any final changes to README.chromium, BUILD.gn, etc.
#    f. Complete the code review process as usual: git cl upload -d;
#       git cl try-results; etc.

PATCHES = [
    'chromium-issue-599427.patch',
    'chromium-issue-628581.patch',
    'libxml2-2.9.4-security-CVE-2017-7376-nanohttp-out-of-bounds-write.patch',
    'libxml2-2.9.4-security-xpath-nodetab-uaf.patch',
    'chromium-issue-708434.patch',
]


# See libxml2 configure.ac and win32/configure.js to learn what
# options are available.

# These two sets of options should be in sync. You can check the
# generated #defines in (win32|mac|linux)/include/libxml.h to confirm
# this.
SHARED_XML_CONFIGURE_OPTIONS = [
    # These options are turned ON
    ('--with-icu', 'icu=yes'),
    # These options are turned OFF
    ('--without-c14n', 'c14n=no'),
    ('--without-catalog', 'catalog=no'),
    ('--without-debug', 'xml_debug=no'),
    ('--without-docbook', 'docb=no'),
    ('--without-ftp', 'ftp=no'),
    ('--without-http', 'http=no'),
    ('--without-iconv', 'iconv=no'),
    ('--without-legacy', 'legacy=no'),
    ('--without-lzma', 'lzma=no'),
    ('--without-mem-debug', 'mem_debug=no'),
    ('--without-modules', 'modules=no'),
    ('--without-regexps', 'regexps=no'),
    ('--without-run-debug', 'run_debug=no'),
    ('--without-schemas', 'schemas=no'),
    ('--without-schematron', 'schematron=no'),
    ('--without-valid', 'valid=no'),
    ('--without-xinclude', 'xinclude=no'),
    ('--without-xptr', 'xptr=no'),
    ('--without-zlib', 'zlib=no'),
]


# These options are only available in configure.ac for Linux and Mac.
EXTRA_NIX_XML_CONFIGURE_OPTIONS = [
    '--without-readline',
    '--without-history',
]


# These options are only available in win32/configure.js for Windows.
EXTRA_WIN32_XML_CONFIGURE_OPTIONS = [
    'walker=no',
]


XML_CONFIGURE_OPTIONS = (
    [option[0] for option in SHARED_XML_CONFIGURE_OPTIONS] +
    EXTRA_NIX_XML_CONFIGURE_OPTIONS)


XML_WIN32_CONFIGURE_OPTIONS = (
    [option[1] for option in SHARED_XML_CONFIGURE_OPTIONS] +
    EXTRA_WIN32_XML_CONFIGURE_OPTIONS)


FILES_TO_REMOVE = [
    'src/DOCBparser.c',
    'src/HACKING',
    'src/INSTALL.libxml2',
    'src/MAINTAINERS',
    'src/Makefile.win',
    'src/README.cvs-commits',
    # This is unneeded "legacy" SAX API, even though we enable SAX1.
    'src/SAX.c',
    'src/VxWorks',
    'src/autogen.sh',
    'src/autom4te.cache',
    'src/bakefile',
    'src/build_glob.py',
    'src/c14n.c',
    'src/catalog.c',
    'src/chvalid.def',
    'src/debugXML.c',
    'src/doc',
    'src/example',
    'src/genChRanges.py',
    'src/global.data',
    'src/include/libxml/xmlversion.h',
    'src/include/libxml/xmlwin32version.h',
    'src/include/libxml/xmlwin32version.h.in',
    'src/legacy.c',
    'src/libxml2.doap',
    'src/macos/libxml2.mcp.xml.sit.hqx',
    'src/optim',
    'src/os400',
    'src/python',
    'src/relaxng.c',
    'src/result',
    'src/rngparser.c',
    'src/schematron.c',
    'src/test',
    'src/testOOM.c',
    'src/testOOMlib.c',
    'src/testOOMlib.h',
    'src/trio.c',
    'src/trio.h',
    'src/triop.h',
    'src/triostr.c',
    'src/triostr.h',
    'src/vms',
    'src/win32/VC10/config.h',
    'src/win32/wince',
    'src/xinclude.c',
    'src/xlink.c',
    'src/xml2-config.in',
    'src/xmlcatalog.c',
    'src/xmllint.c',
    'src/xmlmodule.c',
    'src/xmlregexp.c',
    'src/xmlschemas.c',
    'src/xmlschemastypes.c',
    'src/xpointer.c',
    'src/xstc',
    'src/xzlib.c',
]


THIRD_PARTY_LIBXML_SRC = 'third_party/libxml/src'


class WorkingDir(object):
    """"Changes the working directory and resets it on exit."""
    def __init__(self, path):
        self.prev_path = os.getcwd()
        self.path = path

    def __enter__(self):
        os.chdir(self.path)

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_value:
            print('was in %s; %s before that' % (self.path, self.prev_path))
        os.chdir(self.prev_path)


def git(*args):
    """Runs a git subcommand.

    On Windows this uses the shell because there's a git wrapper
    batch file in depot_tools.

    Arguments:
        args: The arguments to pass to git.
    """
    command = ['git'] + list(args)
    subprocess.check_call(command, shell=(os.name == 'nt'))


def remove_tracked_and_local_dir(path):
    """Removes the contents of a directory from git, and the filesystem.

    Arguments:
        path: The path to remove.
    """
    remove_tracked_files([path])
    shutil.rmtree(path, ignore_errors=True)
    os.mkdir(path)


def remove_tracked_files(files_to_remove):
    """Removes tracked files from git.

    Arguments:
        files_to_remove: The files to remove.
    """
    files_to_remove = [f for f in files_to_remove if os.path.exists(f)]
    git('rm', '-rf', *files_to_remove)


def sed_in_place(input_filename, program):
    """Replaces text in a file.

    Arguments:
        input_filename: The file to edit.
        program: The sed program to perform edits on the file.
    """
    # OS X's sed requires -e
    subprocess.check_call(['sed', '-i', '-e', program, input_filename])


def check_copying(full_path_to_third_party_libxml_src):
    path = os.path.join(full_path_to_third_party_libxml_src, 'COPYING')
    if not os.path.exists(path):
        return
    with open(path) as f:
        s = f.read()
        if 'GNU' in s:
            raise Exception('check COPYING')


def prepare_libxml_distribution(libxml2_repo_path, temp_dir):
    """Makes a libxml2 distribution.

    Args:
        libxml2_repo_path: The path to the local clone of the libxml2 repo.
        temp_dir: A temporary directory to stage the distribution to.

    Returns: A tuple of commit hash and full path to the archive.
    """
    # If it was necessary to push from a distribution prepared upstream,
    # this is the point to inject it: Return the version string and the
    # distribution tar file.

    # The libxml2 repo we're pulling changes from should not have
    # local changes. This *should* be a commit that's publicly visible
    # in the upstream repo; reviewers should check this.
    check_clean(libxml2_repo_path)

    temp_config_path = os.path.join(temp_dir, 'config')
    os.mkdir(temp_config_path)
    temp_src_path = os.path.join(temp_dir, 'src')
    os.mkdir(temp_src_path)

    with WorkingDir(libxml2_repo_path):
        commit = subprocess.check_output(
            ['git', 'log', '-n', '1', '--pretty=format:%H', 'HEAD'])
        subprocess.check_call(
            'git archive HEAD | tar -x -C "%s"' % temp_src_path,
            shell=True)
    with WorkingDir(temp_src_path):
        os.remove('.gitignore')
    with WorkingDir(temp_config_path):
        subprocess.check_call(['../src/autogen.sh'] + XML_CONFIGURE_OPTIONS)
        subprocess.check_call(['make', 'dist-all'])

        # Work out what it is called
        tar_file = subprocess.check_output(
            '''awk '/PACKAGE =/ {p=$3} /VERSION =/ {v=$3} '''
            '''END {printf("%s-%s.tar.gz", p, v)}' Makefile''',
            shell=True)
        return commit, os.path.abspath(tar_file)


def roll_libxml_linux(src_path, libxml2_repo_path):
    with WorkingDir(src_path):
        # Export the upstream git repo.
        try:
            temp_dir = tempfile.mkdtemp()
            print('temporary directory: %s' % temp_dir)

            commit, tar_file = prepare_libxml_distribution(libxml2_repo_path,
                                                           temp_dir)

            # Remove all of the old libxml to ensure only desired cruft
            # accumulates
            remove_tracked_and_local_dir(THIRD_PARTY_LIBXML_SRC)

            # Update the libxml repo and export it to the Chromium tree
            with WorkingDir(THIRD_PARTY_LIBXML_SRC):
                subprocess.check_call(
                    'tar xzf %s --strip-components=1' % tar_file,
                    shell=True)
        finally:
            shutil.rmtree(temp_dir)

        with WorkingDir(THIRD_PARTY_LIBXML_SRC):
            # Put the version number is the README file
            sed_in_place('../README.chromium',
                         's/Version: .*$/Version: %s/' % commit)

            for patch in PATCHES:
                print(patch)
                subprocess.check_call(
                    'cat ../chromium/%s | patch -p1 --fuzz=0' % patch,
                    shell=True)

            with WorkingDir('../linux'):
                subprocess.check_call(
                    ['../src/autogen.sh'] + XML_CONFIGURE_OPTIONS)
                check_copying(os.getcwd())
                sed_in_place('config.h', 's/#define HAVE_RAND_R 1//')

            # Add *everything*
            with WorkingDir('../src'):
                git('add', '*')
                git('commit', '-am', '%s libxml, linux' % commit)
    print('Now push to Windows and run steps there.')


def roll_libxml_win32(src_path):
    with WorkingDir(src_path):
        # Run the configure script.
        with WorkingDir(os.path.join(THIRD_PARTY_LIBXML_SRC, 'win32')):
            subprocess.check_call(
                ['cscript', '//E:jscript', 'configure.js', 'compiler=msvc'] +
                XML_WIN32_CONFIGURE_OPTIONS)

            # Add and commit the result.
            shutil.move('VC10/config.h', '../../win32/config.h')
            git('add', '../../win32/config.h')
            shutil.move('../include/libxml/xmlversion.h',
                        '../../win32/include/libxml/xmlversion.h')
            git('add', '../../win32/include/libxml/xmlversion.h')
            git('commit', '-m', 'Windows')
            git('clean', '-f')
    print('Now push to Mac and run steps there.')


def roll_libxml_mac(src_path):
    full_path_to_third_party_libxml = os.path.join(
        src_path, THIRD_PARTY_LIBXML_SRC, '..')

    with WorkingDir(os.path.join(full_path_to_third_party_libxml, 'mac')):
        subprocess.check_call(['autoreconf', '-i', '../src'])
        subprocess.check_call(['../src/configure'] + XML_CONFIGURE_OPTIONS)
        sed_in_place('config.h', 's/#define HAVE_RAND_R 1//')

    with WorkingDir(full_path_to_third_party_libxml):
        commit = subprocess.check_output(['awk', '/Version:/ {print $2}',
                                          'README.chromium'])
        remove_tracked_files(FILES_TO_REMOVE)
        commit_message = 'Roll libxml to %s' % commit
        git('commit', '-am', commit_message)
    print('Now upload for review, etc.')


def check_clean(path):
    with WorkingDir(path):
        status = subprocess.check_output(['git', 'status', '-s'])
        if len(status) > 0:
            raise Exception('repository at %s is not clean' % path)


def main():
    src_dir = os.getcwd()
    if not os.path.exists(os.path.join(src_dir, 'third_party')):
        print('error: run this script from the Chromium src directory')
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='Roll the libxml2 dependency in Chromium')
    platform = parser.add_mutually_exclusive_group(required=True)
    platform.add_argument('--linux', action='store_true')
    platform.add_argument('--win32', action='store_true')
    platform.add_argument('--mac', action='store_true')
    parser.add_argument(
        'libxml2_repo_path',
        type=str,
        nargs='?',
        help='The path to the local clone of the libxml2 git repo.')
    args = parser.parse_args()

    if args.linux:
        libxml2_repo_path = args.libxml2_repo_path
        if not libxml2_repo_path:
            print('Specify the path to the local libxml2 repo clone.')
            sys.exit(1)
        libxml2_repo_path = os.path.abspath(libxml2_repo_path)
        roll_libxml_linux(src_dir, libxml2_repo_path)
    elif args.win32:
        roll_libxml_win32(src_dir)
    elif args.mac:
        roll_libxml_mac(src_dir)


if __name__ == '__main__':
    main()
