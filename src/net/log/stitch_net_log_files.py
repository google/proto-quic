#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

'''
This script stitches the NetLog files in a specified directory.

The complete NetLog will be written to net-internals-log.json in the directory
passed as argument to --path.
'''

import argparse, os

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--path', action='store',
      help="Specifies the complete filepath of the directory where the log "
      "files are located.")
  # TODO(dconnol): Automatically pull all event files matching the format
  # event_file_<num>.json and remove the num_files argument.
  parser.add_argument('--num_files', action='store',
      help="Specifies the number of event files (not including the constants "
      "file or the end_netlog file) that need need to be stitched together. "
      "The number of event files passed to the script must not be greater "
      "than the number of event files in the directory.")
  args = parser.parse_args()

  num_files = int(args.num_files)
  filepath = args.path
  if filepath[-1:] != "/":
    filepath += "/"

  os.chdir(filepath)

  with open("net-internals-log.json", "w") as stitched_file:
    try:
      file = open("constants.json")
      with file:
        for line in file:
          stitched_file.write(line)
    except IOError:
      os.remove("net-internals-log.json")
      print "File \"constants.json\" not found."
      return

    events_written = False;
    for i in range(num_files):
      try:
        file = open("event_file_%d.json" % i)
        with file:
          if not events_written:
            line = file.readline();
            events_written = True
          for next_line in file:
            if next_line.strip() == "":
              line += next_line
            else:
              stitched_file.write(line)
              line = next_line
      except IOError:
        os.remove("net-internals-log.json")
        print "File \"event_file_%d.json\" not found." % i
        return
    # Remove hanging comma from last event
    # TODO(dconnol): Check if the last line is a valid JSON object. If not,
    # do not write the line to file. This handles incomplete logs.
    line = line.strip()
    if line[-1:] == ",":
      stitched_file.write(line[:-1])
    elif line:
      raise ValueError('Last event is not properly formed')

    try:
      file = open("end_netlog.json")
      with file:
        for line in file:
          stitched_file.write(line)
    except IOError:
        os.remove("net-internals-log.json")
        print "File \"end_netlog\" not found."
        return

  # Delete old NetLog files
  for i in range (num_files):
    os.remove("event_file_%d.json" % i)
  os.remove("constants.json")
  os.remove("end_netlog.json")


if __name__ == "__main__":
  main()
