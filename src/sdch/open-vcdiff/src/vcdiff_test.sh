#!/bin/sh
#
# Copyright 2008 The open-vcdiff Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script tests the correctness of the vcdiff command-line executable.
# If you add a new test here, please add the same test to the Windows script
# src/vcdiff_test.bat.
#
# The caller should pass path to PROJECT_SOURCE_DIR to this script. CTest
# automatically pass it from ```make test```

srcdir=$1
# Find input files
VCDIFF=./vcdiff
# These options are only needed for the encoder;
# the decoder will recognize the interleaved and checksum formats
# without needing to specify any options.
VCD_OPTIONS="-interleaved -checksum"
DICTIONARY_FILE=$srcdir/testdata/configure.ac.v0.1
TARGET_FILE=$srcdir/testdata/configure.ac.v0.2
TEST_TMPDIR=${TMPDIR-/tmp}
DELTA_FILE=$TEST_TMPDIR/configure.ac.vcdiff
OUTPUT_TARGET_FILE=$TEST_TMPDIR/configure.ac.output
MALICIOUS_ENCODING=$srcdir/testdata/allocates_4gb.vcdiff
OVERFLOW_DELTA_FILE=$srcdir/testdata/size-overflow-delta
OVERFLOW_DICTIONARY_FILE=$srcdir/testdata/size-overflow-dictionary
OVERFLOW_ERROR_32=$srcdir/testdata/size-overflow-error-32
OVERFLOW_ERROR_64=$srcdir/testdata/size-overflow-error-64

# vcdiff with no arguments shows usage information & error result
$VCDIFF \
&& { echo "vcdiff with no arguments should fail, but succeeded"; \
     exit 1; }
echo "Test 1 ok";

# vcdiff with three arguments but without "encode" or "decode"
# shows usage information & error result
$VCDIFF $VCD_OPTIONS \
        -dictionary $DICTIONARY_FILE -target $TARGET_FILE -delta $DELTA_FILE \
&& { echo "vcdiff without operation argument should fail, but succeeded"; \
     exit 1; }
echo "Test 2 ok";

# vcdiff with all three arguments.  Verify that output file matches target file
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
|| { echo "Encode with three arguments failed"; \
     exit 1; }
$VCDIFF decode -dictionary $DICTIONARY_FILE \
               -delta $DELTA_FILE \
               -target $OUTPUT_TARGET_FILE \
|| { echo "Decode with three arguments failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 3 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

# vcdiff using stdin/stdout.  Verify that output file matches target file
{ $VCDIFF $VCD_OPTIONS \
          encode -dictionary $DICTIONARY_FILE \
                 < $TARGET_FILE \
                 > $DELTA_FILE; } \
|| { echo "Encode using stdin/stdout failed"; \
     exit 1; }
{ $VCDIFF decode -dictionary $DICTIONARY_FILE \
                 < $DELTA_FILE \
                 > $OUTPUT_TARGET_FILE; } \
|| { echo "Decode using stdin/stdout failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 4 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

# vcdiff with mixed stdin/stdout.
{ $VCDIFF $VCD_OPTIONS \
          encode -dictionary $DICTIONARY_FILE \
                 -target $TARGET_FILE \
                 > $DELTA_FILE; } \
|| { echo "Encode with mixed arguments failed"; \
     exit 1; }
{ $VCDIFF decode -dictionary $DICTIONARY_FILE \
                 -delta $DELTA_FILE \
                 > $OUTPUT_TARGET_FILE; } \
|| { echo "Decode with mixed arguments failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 5 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

{ $VCDIFF $VCD_OPTIONS \
          encode -dictionary $DICTIONARY_FILE \
                 < $TARGET_FILE \
                 -delta $DELTA_FILE; } \
|| { echo "Encode with mixed arguments failed"; \
     exit 1; }
{ $VCDIFF decode -dictionary $DICTIONARY_FILE \
                 < $DELTA_FILE \
                 -target $OUTPUT_TARGET_FILE; } \
|| { echo "Decode with mixed arguments failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 6 ok";

rm $OUTPUT_TARGET_FILE
# Don't remove $DELTA_FILE; use it for the next test

# If using the wrong dictionary, and dictionary is smaller than the original
# dictionary, vcdiff will spot the mistake and return an error.  (It can't
# detect the case where the wrong dictionary is larger than the right one.)
$VCDIFF decode -dictionary $TARGET_FILE \
               -delta $DELTA_FILE \
               -target $OUTPUT_TARGET_FILE \
&& { echo "Decode using larger dictionary should fail, but succeeded"; \
     exit 1; }
echo "Test 7 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

# "vcdiff test" with all three arguments.
$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
|| { echo "vcdiff test with three arguments failed"; \
     exit 1; }
echo "Test 8 ok";

rm $DELTA_FILE

# Dictionary file not found.
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $TEST_TMPDIR/nonexistent_file \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
&& { echo "vcdiff with missing dictionary file should fail, but succeeded"; \
     exit 1; }
echo "Test 9 ok";

# Target file not found.
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TEST_TMPDIR/nonexistent_file \
               -delta $DELTA_FILE \
&& { echo "vcdiff with missing target file should fail, but succeeded"; \
     exit 1; }
echo "Test 10 ok";

# Delta file not found.
$VCDIFF decode -dictionary $DICTIONARY_FILE \
               -delta $TEST_TMPDIR/nonexistent_file \
               -target $OUTPUT_TARGET_FILE \
&& { echo "vcdiff with missing delta file should fail, but succeeded"; \
     exit 1; }
echo "Test 11 ok";

# Try traversing an infinite loop of symbolic links.
ln -s $TEST_TMPDIR/infinite_loop1 $TEST_TMPDIR/infinite_loop2
ln -s $TEST_TMPDIR/infinite_loop2 $TEST_TMPDIR/infinite_loop1
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $TEST_TMPDIR/infinite_loop1 \
               -target $TEST_TMPDIR/infinite_loop2 \
               -delta $DELTA_FILE \
&& { echo "vcdiff with symbolic link loop should fail, but succeeded"; \
     exit 1; }
echo "Test 12 ok";

rm $TEST_TMPDIR/infinite_loop1 $TEST_TMPDIR/infinite_loop2

# Test using -stats flag
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
               -stats \
|| { echo "Encode with -stats failed"; \
     exit 1; }
$VCDIFF -stats \
        decode -dictionary $DICTIONARY_FILE \
               -delta $DELTA_FILE \
               -target $OUTPUT_TARGET_FILE \
|| { echo "Decode with -stats failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 13 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

# Using /dev/null as dictionary should work, but (because dictionary is empty)
# it will not produce a small delta file.
$VCDIFF $VCD_OPTIONS \
        test -dictionary /dev/null \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -stats \
|| { echo "vcdiff test with /dev/null as dictionary failed"; \
     exit 1; }
echo "Test 14 ok";

rm $DELTA_FILE

# Using /dev/kmem as dictionary or target should produce an error
# (permission denied, or too large, or special file type)
$VCDIFF $VCD_OPTIONS \
        encode -dictionary /dev/kmem \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
&& { echo "vcdiff with /dev/kmem as dictionary should fail, but succeeded"; \
     exit 1; }
echo "Test 15 ok";

$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target /dev/kmem \
               -delta $DELTA_FILE \
&& { echo "vcdiff with /dev/kmem as target should fail, but succeeded"; \
     exit 1; }
echo "Test 16 ok";

# Decode using something that isn't a delta file
$VCDIFF decode -dictionary $DICTIONARY_FILE \
               -delta /etc/fstab \
               -target $OUTPUT_TARGET_FILE \
&& { echo "vcdiff with invalid delta file should fail, but succeeded"; \
     exit 1; }
echo "Test 17 ok";

$VCDIFF $VCD_OPTIONS \
        encode -target $TARGET_FILE \
               -delta $DELTA_FILE \
               -dictionary \
&& { echo "-dictionary option with no file name should fail, but succeeded"; \
     exit 1; }
echo "Test 18 ok";

$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -delta $DELTA_FILE \
               -target \
&& { echo "-target option with no file name should fail, but succeeded"; \
     exit 1; }
echo "Test 19 ok";

$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TARGET_FILE \
               -delta \
&& { echo "-delta option with no file name should fail, but succeeded"; \
     exit 1; }
echo "Test 20 ok";

$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
               -buffersize \
&& { echo "-buffersize option with no argument should fail, but succeeded"; \
     exit 1; }
echo "Test 21 ok";

# Using -buffersize=1 should still work.
$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -buffersize 1 \
             -stats \
|| { echo "vcdiff test with -buffersize=1 failed"; \
     exit 1; }
echo "Test 22 ok";

rm $DELTA_FILE

# Using -buffersize=1 with stdin/stdout means that vcdiff
# will create a separate target window for each byte read.
{ $VCDIFF encode -dictionary $DICTIONARY_FILE \
                 -buffersize 1 \
                 -stats \
                 < $TARGET_FILE \
                 > $DELTA_FILE; } \
|| { echo "Encode using stdin/stdout with -buffersize=1 failed"; \
     exit 1; }
{ $VCDIFF decode -dictionary $DICTIONARY_FILE \
                 -buffersize 1 \
                 -stats \
                 < $DELTA_FILE \
                 > $OUTPUT_TARGET_FILE; } \
|| { echo "Decode using stdin/stdout with -buffersize=1 failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original with -buffersize=1"; \
     exit 1; }
echo "Test 23 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

# Using -buffersize=0 should fail.
$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -buffersize 0 \
&& { echo "vcdiff test with -buffersize=0 should fail, but succeeded"; \
     exit 1; }
echo "Test 24 ok";

rm $DELTA_FILE

# Using -buffersize=128M (larger than default maximum) should still work.
$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -buffersize 134217728 \
             -stats \
|| { echo "vcdiff test with -buffersize=128M failed"; \
     exit 1; }
echo "Test 25 ok";

rm $DELTA_FILE

$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -froobish \
&& { echo "vdiff test with unrecognized option should fail, but succeeded"; \
     exit 1; }
echo "Test 26 ok";

$VCDIFF $VCD_OPTIONS \
        encode -target $TARGET_FILE \
               -delta $DELTA_FILE \
&& { echo "encode with no dictionary option should fail, but succeeded"; \
     exit 1; }
echo "Test 27 ok";

$VCDIFF decode -target $TARGET_FILE \
               -delta $DELTA_FILE \
&& { echo "decode with no dictionary option should fail, but succeeded"; \
     exit 1; }
echo "Test 28 ok";

# Remove -interleaved and -checksum options
{ $VCDIFF encode -dictionary $DICTIONARY_FILE \
                 < $TARGET_FILE \
                 > $DELTA_FILE; } \
|| { echo "Encode without -interleaved and -checksum options failed"; \
     exit 1; }
{ $VCDIFF decode -dictionary $DICTIONARY_FILE \
                 < $DELTA_FILE \
                 > $OUTPUT_TARGET_FILE; } \
|| { echo "Decode non-interleaved output failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original with -interleaved"; \
     exit 1; }
echo "Test 29 ok";

# -target_matches option
{ $VCDIFF encode -dictionary $DICTIONARY_FILE \
                 -target_matches \
                 -stats \
                 < $TARGET_FILE \
                 > $DELTA_FILE; } \
|| { echo "Encode with -target_matches option failed"; \
     exit 1; }
# The decode operation ignores the -target_matches option.
{ $VCDIFF decode -dictionary $DICTIONARY_FILE \
                 < $DELTA_FILE \
                 > $OUTPUT_TARGET_FILE; } \
|| { echo "Decode output failed with -target_matches"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original with -target_matches"; \
     exit 1; }
echo "Test 30 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

$VCDIFF $VCD_OPTIONS \
        dencode -dictionary $DICTIONARY_FILE \
                -target $TARGET_FILE \
                -delta $DELTA_FILE \
&& { echo "vdiff with unrecognized action should fail, but succeeded"; \
     exit 1; }
echo "Test 31 ok";

$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
&& { echo "vdiff test without delta option should fail, but succeeded"; \
     exit 1; }
echo "Test 32 ok";

$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -delta $DELTA_FILE \
&& { echo "vdiff test without target option should fail, but succeeded"; \
     exit 1; }
echo "Test 33 ok";

# open-vcdiff bug 8 (https://github.com/google/open-vcdiff/issues/8)
# A malicious encoding that tries to produce a 4GB target file made up of 64
# windows, each window having a size of 64MB.
# Limit memory usage to 256MB per process, so the test doesn't take forever
# to run out of memory.
OLD_ULIMIT=$(ulimit -v)
echo "Old ulimit: $OLD_ULIMIT"
ulimit -S -v 262144
echo "New ulimit: $(ulimit -v)"

$VCDIFF $VCD_OPTIONS \
    decode -dictionary $DICTIONARY_FILE \
           -delta $MALICIOUS_ENCODING \
           -target /dev/null \
           -max_target_file_size=65536 \
&& { echo "Decoding malicious file should fail, but succeeded"; \
     exit 1; }
echo "Test 34 ok";

$VCDIFF $VCD_OPTIONS \
    decode -dictionary $DICTIONARY_FILE \
           -delta $MALICIOUS_ENCODING \
           -target /dev/null \
           -max_target_window_size=65536 \
&& { echo "Decoding malicious file should fail, but succeeded"; \
     exit 1; }
echo "Test 35 ok";

ulimit -S -v $OLD_ULIMIT

# Decoding a small target with the -max_target_file_size option should succeed.
$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -max_target_file_size=65536 \
|| { echo "vcdiff test with -max_target_file_size failed"; \
     exit 1; }
echo "Test 36 ok";

# Decoding a small target with -max_target_window_size option should succeed.
$VCDIFF $VCD_OPTIONS \
        test -dictionary $DICTIONARY_FILE \
             -target $TARGET_FILE \
             -delta $DELTA_FILE \
             -max_target_window_size=65536 \
|| { echo "vcdiff test with -max_target_window_size failed"; \
     exit 1; }
echo "Test 37 ok";

rm $DELTA_FILE

# Test using -allow_vcd_target=false
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
               -allow_vcd_target=false \
|| { echo "Encode with -allow_vcd_target=false failed"; \
     exit 1; }
$VCDIFF $VCD_OPTIONS \
        decode -dictionary $DICTIONARY_FILE \
               -delta $DELTA_FILE \
               -target $OUTPUT_TARGET_FILE \
               -allow_vcd_target=false \
|| { echo "Decode with -allow_vcd_target=false failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 38 ok";

rm $DELTA_FILE
rm $OUTPUT_TARGET_FILE

# Test using -allow_vcd_target=true
$VCDIFF $VCD_OPTIONS \
        encode -dictionary $DICTIONARY_FILE \
               -target $TARGET_FILE \
               -delta $DELTA_FILE \
               -allow_vcd_target=true \
|| { echo "Encode with -allow_vcd_target=true failed"; \
     exit 1; }
$VCDIFF $VCD_OPTIONS \
        decode -dictionary $DICTIONARY_FILE \
               -delta $DELTA_FILE \
               -target $OUTPUT_TARGET_FILE \
               -allow_vcd_target=true \
|| { echo "Decode with -allow_vcd_target=true failed"; \
     exit 1; }
cmp $TARGET_FILE $OUTPUT_TARGET_FILE \
|| { echo "Decoded target does not match original"; \
     exit 1; }
echo "Test 39 ok";

# Test for overflow in size parsing. Check for the specific overflow error
# message and make sure that it's emitted.
$VCDIFF $VCD_OPTIONS \
        decode -dictionary $OVERFLOW_DICTIONARY_FILE \
               -delta $OVERFLOW_DELTA_FILE \
               -target $OUTPUT_TARGET_FILE 2>$TEST_TMPDIR/overflow-err\
&& { echo "Size overflow didn't crash or error vcdiff"; \
     exit 1; }
cmp $TEST_TMPDIR/overflow-err $OVERFLOW_ERROR_32 \
|| cmp $TEST_TMPDIR/overflow-err $OVERFLOW_ERROR_64 \
|| { echo "Overflow error message does not match"; \
     exit 1; }
echo "Test 40 ok"

echo "PASS"
