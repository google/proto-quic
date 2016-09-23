# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""
This retrieves the latest warnings from the Chrome /analyze build machine, and
does a diff.
This script is intended to be run from retrieve_latest_warnings.bat which
fills out the functionality.
"""

import urllib
import sys
import glob
import os

if len(sys.argv) < 2:
  print "Missing build number."
  sys.exit(10)

buildNumber = int(sys.argv[1])

baseURL = "http://build.chromium.org/p/chromium.fyi/builders/" + \
  "Chromium%20Windows%20Analyze/"

print "Finding recent builds on %s" % baseURL
baseData = urllib.urlopen(baseURL).read()
recentOff = baseData.find("Recent Builds:")
buildPattern = 'success</td>    <td><a href="' + \
  '../../builders/Chromium%20Windows%20Analyze/builds/'
# For some reason I couldn't get regular expressions to work on this data.
latestBuildOff = baseData.find(buildPattern, recentOff) + len(buildPattern)
if latestBuildOff < len(buildPattern):
  print "Couldn't find successful build."
  sys.exit(10)
latestEndOff = baseData.find('"', latestBuildOff)
latestBuildStr = baseData[latestBuildOff:latestEndOff]
maxBuildNumber = int(latestBuildStr)
if buildNumber > maxBuildNumber:
  print "Requested build number (%d) is too high. Maximum is %d." % \
    (buildNumber, maxBuildNumber)
  sys.exit(10)
# Treat negative numbers specially
if sys.argv[1][0] == '-':
  buildNumber = maxBuildNumber + buildNumber
  if buildNumber < 0:
    buildNumber = 0
  print "Retrieving build number %d of %d" % (buildNumber, maxBuildNumber)

# Found the last summary results in the current directory
results = glob.glob("analyze*_summary.txt")
results.sort()
previous = "%04d" % (buildNumber - 1)
if results:
  possiblePrevious = results[-1][7:11]
  if int(possiblePrevious) == buildNumber:
    if len(results) > 1:
      previous = results[-2][7:11]
  else:
    previous = possiblePrevious

dataURL = baseURL + "builds/" + str(buildNumber) + "/steps/compile/logs/stdio"
revisionURL = baseURL + "builds/" + str(buildNumber)

# Retrieve the revision
revisionData = urllib.urlopen(revisionURL).read()
key = "Got Revision</td><td>"
Off = revisionData.find(key) + len(key)
if Off > len(key):
  revision = revisionData[Off: Off + 40]
  print "Revision is '%s'" % revision
  print "Environment variables can be set with set_analyze_revision.bat"
  payload = "set ANALYZE_REVISION=%s\r\n" % revision
  payload += "set ANALYZE_BUILD_NUMBER=%04d\r\n" % buildNumber
  payload += "set ANALYZE_PREV_BUILD_NUMBER=%s\r\n" % previous
  open("set_analyze_revision.bat", "wt").write(payload)

  # Retrieve the raw warning data
  print "Retrieving raw build results. Please wait."
  data = urllib.urlopen(dataURL).read()
  if data.count("status: SUCCESS") == 0:
    print "Build failed or is incomplete."
  else:
    # Fix up "'" and '"'
    data = data.replace("&#39;", "'").replace("&#34;", '"')
    # Fix up '<' and '>'
    data = data.replace("&lt;", "<").replace("&gt;", ">")
    # Fix up '&'
    data = data.replace("&amp;", "&")
    # Fix up random spans
    data = data.replace('</span><span class="stdout">', '')
    # Fix up the source paths to match my local /analyze repo
    if "ANALYZE_REPO" in os.environ:
      sourcePath = r"e:\b\build\slave\chromium_windows_analyze\build\src"
      destPath = os.path.join(os.environ["ANALYZE_REPO"], "src")
      data = data.replace(sourcePath, destPath)
    outputName = "analyze%04d_full.txt" % buildNumber
    open(outputName, "w").write(data)
    print "Done. Data is in %s" % outputName
else:
  print "No revision information found!"
