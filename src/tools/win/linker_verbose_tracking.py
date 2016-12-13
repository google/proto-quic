# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
This script parses the /verbose output from the VC++ linker and uses it to
explain why a particular object file is being linked in. It parses records
like these:

      Found "public: static void * __cdecl SkTLS::Get(void * (__cdecl*)(void)...
        Referenced in chrome_crash_reporter_client_win.obj
        Referenced in skia.lib(SkError.obj)
        Loaded skia.lib(SkTLS.obj)

and then uses the information to answer questions such as "why is SkTLS.obj
being linked in. In this case it was requested by SkError.obj, and the process
is then repeated for SkError.obj. It traces the dependency tree back to a file
that was specified on the command line. Typically that file is part of a
source_set, and if that source_set is causing unnecessary code and data to be
pulled in then changing it to a static_library may reduce the binary size. See
crrev.com/2556603002 for an example of a ~900 KB savings from such a change.

In other cases the source_set to static_library fix does not work because some
of the symbols are required, while others are pulling in unwanted object files.
In these cases it can be necessary to see what symbol is causing one object file
to reference another. Removing or moving the problematic symbol can fix the
problem. See crrev.com/2559063002 for an example of such a change.

One complication is that there are sometimes multiple source files with the
same name, such as crc.c, which can make analysis more difficult or
ambiguous. If this becomes a blocking issue they it may be necessary to
temporarily rename the source file.

Object file name matching is case sensitive.

Typical output when run on chrome.dll verbose link output is:

>python tools\win\linker_verbose_tracking.py chrome_verbose_02.txt flac_crc
Database loaded - 11277 xrefs found
flac_crc.obj pulled in for symbol "_FLAC__crc8" by
        stream_decoder.obj
        bitwriter.obj

stream_decoder.obj pulled in for symbol "_FLAC__stream_decoder_new" by
        stream_encoder.obj
bitwriter.obj pulled in for symbol "_FLAC__bitwriter_new" by
        stream_encoder.obj

stream_encoder.obj pulled in for symbol "_FLAC__stream_encoder_new" by
        Command-line obj file: audio_encoder.obj
"""

import pdb
import re
import sys

def ParseVerbose(input_file):
  # This matches line like this:
  #   Referenced in skia.lib(SkError.obj)
  # with the groups()[0] referring to the object file name without the file
  # extension.
  obj_match = re.compile('.*\((.*)\.obj\)')
  # Prefix used for symbols that are referenced:
  found_prefix = '      Found'

  cross_refs = {}
  cross_refed_symbols = {}

  references = None
  for line in open(input_file):
    if line.startswith(found_prefix):
      references = []
      # Grab the symbol name
      symbol = line[len(found_prefix):].strip()
      if symbol[0] == '"':
        # Strip off leading and trailing quotes if present.
        symbol = symbol[1:-1]
      continue
    if type(references) == type([]):
      sub_line = line.strip()
      match = obj_match.match(sub_line)
      # See if the line is part of the list of places where this symbol was
      # referenced
      if sub_line.count('Referenced ') > 0:
        if match:
          # This indicates a match that is xxx.lib(yyy.obj), so a referencing
          # .obj file that was itself inside of a library. We discard the
          # library name.
          reference = match.groups()[0]
        else:
          # This indicates a match that is just a pure .obj file name
          # I think this means that the .obj file was specified on the linker
          # command line.
          reference = ('Command-line obj file: ' +
                       sub_line[len('Referenced in '): -len('.obj')])
        references.append(reference)
      elif sub_line.count('Loaded ') > 0:
        if match:
          loaded = match.groups()[0]
          cross_refs[loaded] = references
          cross_refed_symbols[loaded] = symbol
        references = None
    if line.startswith('Finished pass 1'):
      # Stop now because the remaining 90% of the verbose output is
      # not of interest. Could probably use /VERBOSE:REF to trim out
      # boring information.
      break
  return cross_refs, cross_refed_symbols


def TrackObj(cross_refs, cross_refed_symbols, obj_name):
  if obj_name.lower().endswith('.obj'):
    obj_name = obj_name[:-len('.obj')]

  # Keep track of which references we've already followed.
  tracked = {}

  # Initial set of object files that we are tracking.
  targets = [obj_name]
  printed = False
  for i in range(100):
    new_targets = {}
    for target in targets:
      if not target in tracked:
        tracked[target] = True
        if target in cross_refs.keys():
          symbol = cross_refed_symbols[target]
          printed = True
          print '%s.obj pulled in for symbol "%s" by' % (target, symbol)
          for ref in cross_refs[target]:
            print '\t%s.obj' % ref
            new_targets[ref] = True
    if len(new_targets) == 0:
      break
    print
    targets = new_targets.keys()
  if not printed:
    print 'No references to %s.obj found.' % obj_name


def main():
  if len(sys.argv) < 3:
    print r'Usage: %s <verbose_output_file> <objfile>' % sys.argv[0]
    print r'Sample: %s chrome_dll_verbose.txt SkTLS' % sys.argv[0]
    return 0
  cross_refs, cross_refed_symbols = ParseVerbose(sys.argv[1])
  print 'Database loaded - %d xrefs found' % len(cross_refs)
  TrackObj(cross_refs, cross_refed_symbols, sys.argv[2])

if __name__ == '__main__':
  sys.exit(main())
