#!/bin/sh
# Copyright 2008 The open-vcdiff Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# These are the files that this script might edit:
#    aclocal.m4 configure Makefile.in src/config.h.in \
#    depcomp config.guess config.sub install-sh missing mkinstalldirs \
#    ltmain.sh
#
# Here's a command you can run to see what files aclocal will import:
#  aclocal -I ../autoconf --output=- | sed -n 's/^m4_include..\([^]]*\).*/\1/p'

set -ex
rm -rf autom4te.cache

trap 'rm -f aclocal.m4.tmp' EXIT

# Use version 1.11 of aclocal and automake if available.
ACLOCAL=aclocal-1.11
if test -z `which "$ACLOCAL"`; then
  ACLOCAL=aclocal
fi

AUTOMAKE=automake-1.11
if test -z `which "$AUTOMAKE"`; then
  AUTOMAKE=automake
fi

# glibtoolize is used for Mac OS X
LIBTOOLIZE=libtoolize
if test -z `which "$LIBTOOLIZE"`; then
  LIBTOOLIZE=glibtoolize
fi

# aclocal tries to overwrite aclocal.m4 even if the contents haven't
# changed, which is annoying when the file is not open for edit (in
# p4).  We work around this by writing to a temp file and just
# updating the timestamp if the file hasn't change.
"$ACLOCAL" --force -I m4 -I gflags/m4 --output=aclocal.m4.tmp
if cmp aclocal.m4.tmp aclocal.m4; then
  touch aclocal.m4               # pretend that we regenerated the file
  rm -f aclocal.m4.tmp
else
  mv aclocal.m4.tmp aclocal.m4   # we did set -e above, so we die if this fails
fi

grep -q LIBTOOL configure.ac && "$LIBTOOLIZE" -c -f
autoconf -f -W all,no-obsolete
autoheader -f -W all
"$AUTOMAKE" -a -c -f -W all

rm -rf autom4te.cache
exit 0
