#!/usr/bin/python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Use: ../mergetraces.py `ls cyglog.* -Sr` > merged_cyglog

""""Merge multiple logs files from different processes into a single log.

Given two log files of execution traces, merge the traces into a single trace.
Merging will use timestamps (i.e. the first two columns of logged calls) to
create a single log that is an ordered trace of calls by both processes.
"""

import optparse
import string
import sys


def ParseLogLines(lines):
  """Parse log file lines.

  Args:
    lines: lines from log file produced by profiled run

    Below is an example of a small log file:
    5086e000-52e92000 r-xp 00000000 b3:02 51276      libchromeview.so
    secs       usecs      pid:threadid    func
    START
    1314897086 795828     3587:1074648168 0x509e105c
    1314897086 795874     3587:1074648168 0x509e0eb4
    1314897086 796326     3587:1074648168 0x509e0e3c
    1314897086 796552     3587:1074648168 0x509e07bc
    END

  Returns:
    tuple conisiting of 1) an ordered list of the logged calls, as an array of
    fields, 2) the virtual start address of the library, used to compute the
    offset of the symbol in the library and 3) the virtual end address
  """
  call_lines = []
  vm_start = 0
  vm_end = 0
  dash_index = lines[0].find ('-')
  space_index = lines[0].find (' ')
  vm_start = int (lines[0][:dash_index], 16)
  vm_end = int (lines[0][dash_index+1:space_index], 16)
  for line in lines[2:]:
    line = line.strip()
    fields = line.split()
    call_lines.append (fields)

  return (call_lines, vm_start, vm_end)


def HasDuplicates(calls):
  """Makes sure that calls are only logged once.

  Args:
    calls: list of calls logged

  Returns:
    boolean indicating if calls has duplicate calls
  """
  seen = set([])
  for call in calls:
    if call[3] in seen:
      return True
    seen.add(call[3])
  return False

def CheckTimestamps(calls):
  """Prints warning to stderr if the call timestamps are not in order.

  Args:
    calls: list of calls logged
  """
  index = 0
  last_timestamp_secs = -1
  last_timestamp_us = -1
  while (index < len (calls)):
    timestamp_secs = int (calls[index][0])
    timestamp_us = int (calls[index][1])
    timestamp = (timestamp_secs * 1000000) + timestamp_us
    last_timestamp = (last_timestamp_secs * 1000000) + last_timestamp_us
    if (timestamp < last_timestamp):
      raise Exception("last_timestamp: " + str(last_timestamp_secs)
                       + " " + str(last_timestamp_us) + " timestamp: "
                       + str(timestamp_secs) + " " + str(timestamp_us) + "\n")
    last_timestamp_secs = timestamp_secs
    last_timestamp_us = timestamp_us
    index = index + 1


def Convert(call_lines, start_address, end_address):
  """Converts the call addresses to static offsets and removes invalid calls.

  Removes profiled calls not in shared library using start and end virtual
  addresses, converts strings to integer values, coverts virtual addresses to
  address in shared library.

  Returns:
     list of calls as tuples (sec, usec, pid:tid, callee)
  """
  converted_calls = []
  call_addresses = set()
  for fields in call_lines:
    secs = int (fields[0])
    usecs = int (fields[1])
    callee = int (fields[3], 16)
    # Eliminate repetitions of the same function.
    if callee in call_addresses:
      continue
    # Eliminate small addresses. It should be safe to do so because these point
    # before the .text section (it is in .plt or earlier).
    # TODO(pasko): understand why __cyg_profile_func_enter may output a small
    # offset sometimes.
    if callee < start_address + 4096:
      sys.stderr.write('WARNING: ignoring small address: %s' %
          hex(callee - start_address))
      call_addresses.add(callee)
      continue
    if start_address <= callee < end_address:
      converted_calls.append((secs, usecs, fields[2], (callee - start_address)))
      call_addresses.add(callee)
  return converted_calls


def Timestamp(trace_entry):
  return int (trace_entry[0]) * 1000000 + int(trace_entry[1])


def AddTrace (tracemap, trace):
  """Adds a trace to the tracemap.

  Adds entries in the trace to the tracemap. All new calls will be added to
  the tracemap. If the calls already exist in the tracemap then they will be
  replaced if they happened sooner in the new trace.

  Args:
    tracemap: the tracemap
    trace: the trace

  """
  for trace_entry in trace:
    call = trace_entry[3]
    if (not call in tracemap) or (
        Timestamp(tracemap[call]) > Timestamp(trace_entry)):
      tracemap[call] = trace_entry


def GroupByProcessAndThreadId(input_trace):
  """Returns an array of traces grouped by pid and tid.

  This is used to make the order of functions not depend on thread scheduling
  which can be greatly impacted when profiling is done with cygprofile. As a
  result each thread has its own contiguous segment of code (ordered by
  timestamp) and processes also have their code isolated (i.e. not interleaved).
  """
  def MakeTimestamp(sec, usec):
    return sec * 1000000 + usec

  def PidAndTidFromString(pid_and_tid):
    strings = pid_and_tid.split(':')
    return (int(strings[0]), int(strings[1]))

  tid_to_pid_map = {}
  pid_first_seen = {}
  tid_first_seen = {}

  for (sec, usec, pid_and_tid, _) in input_trace:
    (pid, tid) = PidAndTidFromString(pid_and_tid)

    # Make sure that thread IDs are unique since this is a property we rely on.
    if tid_to_pid_map.setdefault(tid, pid) != pid:
      raise Exception(
          'Seen PIDs %d and %d for TID=%d. Thread-IDs must be unique' % (
              tid_to_pid_map[tid], pid, tid))

    if not pid in pid_first_seen:
      pid_first_seen[pid] = MakeTimestamp(sec, usec)
    if not tid in tid_first_seen:
      tid_first_seen[tid] = MakeTimestamp(sec, usec)

  def CompareEvents(event1, event2):
    (sec1, usec1, pid_and_tid, _) = event1
    (pid1, tid1) = PidAndTidFromString(pid_and_tid)
    (sec2, usec2, pid_and_tid, _) = event2
    (pid2, tid2) = PidAndTidFromString(pid_and_tid)

    pid_cmp = cmp(pid_first_seen[pid1], pid_first_seen[pid2])
    if pid_cmp != 0:
      return pid_cmp
    tid_cmp = cmp(tid_first_seen[tid1], tid_first_seen[tid2])
    if tid_cmp != 0:
      return tid_cmp
    return cmp(MakeTimestamp(sec1, usec1), MakeTimestamp(sec2, usec2))

  return sorted(input_trace, cmp=CompareEvents)


def Main():
  """Merge two traces for code in specified library and write to stdout.

  Merges the two traces and coverts the virtual addresses to the offsets in the
  library.  First line of merged trace has dummy virtual address of 0-ffffffff
  so that symbolizing the addresses uses the addresses in the log, since the
  addresses have already been converted to static offsets.
  """
  parser = optparse.OptionParser('usage: %prog trace1 ... traceN')
  (_, args) = parser.parse_args()
  if len(args) <= 1:
    parser.error('expected at least the following args: trace1 trace2')

  step = 0

  # Maps function addresses to their corresponding trace entry.
  tracemap = dict()

  for trace_file in args:
    step += 1
    sys.stderr.write("    " + str(step) + "/" + str(len(args)) +
                     ": " + trace_file + ":\n")

    trace_lines = map(string.rstrip, open(trace_file).readlines())
    (trace_calls, trace_start, trace_end) = ParseLogLines(trace_lines)
    CheckTimestamps(trace_calls)
    sys.stderr.write("Len: " + str(len(trace_calls)) +
                     ". Start: " + hex(trace_start) +
                     ", end: " + hex(trace_end) + '\n')

    trace_calls = Convert(trace_calls, trace_start, trace_end)
    sys.stderr.write("Converted len: " + str(len(trace_calls)) + "\n")

    AddTrace(tracemap, trace_calls)
    sys.stderr.write("Merged len: " + str(len(tracemap)) + "\n")

  # Extract the resulting trace from the tracemap
  merged_trace = []
  for call in tracemap:
    merged_trace.append(tracemap[call])
  merged_trace.sort(key=Timestamp)

  grouped_trace = GroupByProcessAndThreadId(merged_trace)

  print "0-ffffffff r-xp 00000000 xx:00 00000 ./"
  print "secs\tusecs\tpid:threadid\tfunc"
  for call in grouped_trace:
    print (str(call[0]) + "\t" + str(call[1]) + "\t" + call[2] + "\t" +
           hex(call[3]))


if __name__ == '__main__':
  Main()
