#!/usr/bin/python
# Copyright (c) 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# TODO(svaldez): Deduplicate various annotate_test_data.

"""This script is called without any arguments to re-format all of the *.pem
files in the script's parent directory.

The main formatting change is to run "openssl asn1parse" for each of the PEM
block sections, and add that output to the comment. It also runs the command
on the OCTET STRING representing BasicOCSPResponse.

"""

import glob
import os
import re
import base64
import subprocess


def Transform(file_data):
  """Returns a transformed (formatted) version of file_data"""

  result = ''

  for block in GetPemBlocks(file_data):
    if len(result) != 0:
      result += '\n'

    # If there was a user comment (non-script-generated comment) associated
    # with the block, output it immediately before the block.
    user_comment = GetUserComment(block.comment)
    if user_comment:
      result += user_comment + '\n'

    generated_comment = GenerateCommentForBlock(block.name, block.data)
    result += generated_comment + '\n'


    result += MakePemBlockString(block.name, block.data)

  return result


def GenerateCommentForBlock(block_name, block_data):
  """Returns a string describing the ASN.1 structure of block_data"""

  p = subprocess.Popen(['openssl', 'asn1parse', '-i', '-inform', 'DER'],
                       stdout=subprocess.PIPE, stdin=subprocess.PIPE,
                       stderr=subprocess.PIPE)
  stdout_data, stderr_data = p.communicate(input=block_data)
  generated_comment = '$ openssl asn1parse -i < [%s]\n%s' % (block_name,
                                                             stdout_data)

  # The OCTET STRING encoded BasicOCSPResponse is also parsed out using
  #'openssl asn1parse'.
  if block_name == 'OCSP RESPONSE':
    if '[HEX DUMP]:' in generated_comment:
      (generated_comment, response) = generated_comment.split('[HEX DUMP]:', 1)
      response = response.replace('\n', '')
      if len(response) % 2 != 0:
        response = '0' + response
      response = GenerateCommentForBlock('INNER', response.decode('hex'))
      response = response.split('\n', 1)[1]
      response = response.replace(': ', ':      ')
      generated_comment += '\n%s' % (response)
  return generated_comment.strip('\n')



def GetUserComment(comment):
  """Removes any script-generated lines (everything after the $ openssl line)"""

  # Consider everything after "$ openssl" to be a generated comment.
  comment = comment.split('$ openssl asn1parse -i', 1)[0]
  if IsEntirelyWhiteSpace(comment):
    comment = ''
  return comment


def MakePemBlockString(name, data):
  return ('-----BEGIN %s-----\n'
          '%s'
          '-----END %s-----\n') % (name, EncodeDataForPem(data), name)


def GetPemFilePaths():
  """Returns an iterable for all the paths to the PEM test files"""

  base_dir = os.path.dirname(os.path.realpath(__file__))
  return glob.iglob(os.path.join(base_dir, '*.pem'))


def ReadFileToString(path):
  with open(path, 'r') as f:
    return f.read()


def WrapTextToLineWidth(text, column_width):
  result = ''
  pos = 0
  while pos < len(text):
    result += text[pos : pos + column_width] + '\n'
    pos += column_width
  return result


def EncodeDataForPem(data):
  result = base64.b64encode(data)
  return WrapTextToLineWidth(result, 75)


class PemBlock(object):
  def __init__(self):
    self.name = None
    self.data = None
    self.comment = None


def StripAllWhitespace(text):
  pattern = re.compile(r'\s+')
  return re.sub(pattern, '', text)


def IsEntirelyWhiteSpace(text):
  return len(StripAllWhitespace(text)) == 0


def DecodePemBlockData(text):
  text = StripAllWhitespace(text)
  return base64.b64decode(text)


def GetPemBlocks(data):
  """Returns an iterable of PemBlock"""

  comment_start = 0

  regex = re.compile(r'-----BEGIN ([\w ]+)-----(.*?)-----END \1-----',
                     re.DOTALL)

  for match in regex.finditer(data):
    block = PemBlock()

    block.name = match.group(1)
    block.data = DecodePemBlockData(match.group(2))

    # Keep track of any non-PEM text above blocks
    block.comment = data[comment_start : match.start()].strip()
    comment_start = match.end()

    yield block


def WriteStringToFile(data, path):
  with open(path, "w") as f:
    f.write(data)


def main():
  for path in GetPemFilePaths():
    print "Processing %s ..." % (path)
    original_data = ReadFileToString(path)
    transformed_data = Transform(original_data)
    if original_data != transformed_data:
      WriteStringToFile(transformed_data, path)
      print "Rewrote %s" % (path)


if __name__ == "__main__":
  main()
