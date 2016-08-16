@echo off
rem Copyright 2008 The open-vcdiff Authors. All Rights Reserved.
rem
rem Licensed under the Apache License, Version 2.0 (the "License");
rem you may not use this file except in compliance with the License.
rem You may obtain a copy of the License at
rem
rem     http:#www.apache.org/licenses/LICENSE-2.0
rem
rem Unless required by applicable law or agreed to in writing, software
rem distributed under the License is distributed on an "AS IS" BASIS,
rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
rem See the License for the specific language governing permissions and
rem limitations under the License.
rem
rem This script tests the correctness of the vcdiff.exe command-line
rem executable.  It is the Windows equivalent of the src/vcdiff_test.sh
rem shell script for Unix systems, though some of the tests from that
rem script are not included here.
rem
rem If you add a new test here, please add the same test to
rem src/vcdiff_test.sh.

rem The script should be passed one argument which is the location of the
rem vcdiff.exe executable.
if not exist %1 ^
    ( echo Must pass location of vcdiff.exe as script argument ^
      &&exit /b 1 )
set VCDIFF=%1

rem These options are only needed for the encoder;
rem the decoder will recognize the interleaved and checksum formats
rem without needing to specify any options.
set TESTDATA_DIR=..\..\testdata
set VCD_OPTIONS=-interleaved -checksum
set DICTIONARY_FILE=%TESTDATA_DIR%\configure.ac.v0.1
set TARGET_FILE=%TESTDATA_DIR%\configure.ac.v0.2
set DELTA_FILE=%TEMP%\configure.ac.vcdiff
set OUTPUT_TARGET_FILE=%TEMP%\configure.ac.output
set MALICIOUS_ENCODING=%TESTDATA_DIR%\allocates_4gb.vcdiff
set EMPTY_FILE=%TESTDATA_DIR%\empty_file.txt

rem vcdiff with no arguments shows usage information & error result
%VCDIFF% ^
    && ( echo vcdiff with no arguments should fail, but succeeded ^
         &&exit /b 1 )
echo Test 1 ok

rem vcdiff with three arguments but without "encode" or "decode"
rem shows usage information & error result
%VCDIFF% %VCD_OPTIONS% ^
         -dictionary %DICTIONARY_FILE% -target %TARGET_FILE% -delta %DELTA_FILE% ^
    && ( echo vcdiff without operation argument should fail, but succeeded ^
         &&exit /b 1 )
echo Test 2 ok

rem vcdiff with all three arguments.  Verify that output file matches target file
%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
    || ( echo Encode with three arguments failed ^
         &&exit /b 1 )
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                -delta %DELTA_FILE% ^
                -target %OUTPUT_TARGET_FILE% ^
    || ( echo Decode with three arguments failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original ^
         &&exit /b 1 )
echo Test 3 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

rem open-vcdiff Issue 7
rem (https://github.com/google/open-vcdiff/issues/7)
rem vcdiff using stdin/stdout.  Verify that output file matches target file
%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                < %TARGET_FILE% ^
                > %DELTA_FILE% ^
    || ( echo Encode using stdin/stdout failed ^
         &&exit /b 1 )
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                < %DELTA_FILE% ^
                > %OUTPUT_TARGET_FILE% ^
    || ( echo Decode using stdin/stdout failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original ^
         &&exit /b 1 )
echo Test 4 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

rem vcdiff with mixed stdin/stdout.
%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -target %TARGET_FILE% ^
                > %DELTA_FILE% ^
    || ( echo Encode with mixed arguments failed ^
         &&exit /b 1 )
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                -delta %DELTA_FILE% ^
                > %OUTPUT_TARGET_FILE% ^
    || ( echo Decode with mixed arguments failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original ^
         &&exit /b 1 )
echo Test 5 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                < %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
    || ( echo Encode with mixed arguments failed ^
         &&exit /b 1 )
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                < %DELTA_FILE% ^
                -target %OUTPUT_TARGET_FILE% ^
    || ( echo Decode with mixed arguments failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original ^
         &&exit /b 1 )
echo Test 6 ok

del %OUTPUT_TARGET_FILE%
rem Don't remove %DELTA_FILE%; use it for the next test

rem If using the wrong dictionary, and dictionary is smaller than the original
rem dictionary, vcdiff will spot the mistake and return an error.  (It can't
rem detect the case where the wrong dictionary is larger than the right one.)
%VCDIFF% decode -dictionary %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
                -target %OUTPUT_TARGET_FILE% ^
    && ( echo Decode using larger dictionary should fail, but succeeded ^
         &&exit /b 1 )
echo Test 7 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

rem "vcdiff test" with all three arguments.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
    || ( echo vcdiff test with three arguments failed ^
         &&exit /b 1 )
echo Test 8 ok

del %DELTA_FILE%

rem Dictionary file not found.
%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %TEMP%\nonexistent_file ^
                -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
    && ( echo vcdiff with missing dictionary file should fail, but succeeded ^
         &&exit /b 1 )
echo Test 9 ok

rem Target file not found.
%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -target %TEMP%\nonexistent_file ^
                -delta %DELTA_FILE% ^
    && ( echo vcdiff with missing target file should fail, but succeeded ^
         &&exit /b 1 )
echo Test 10 ok

rem Delta file not found.
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                -delta %TEMP%\nonexistent_file ^
                -target %OUTPUT_TARGET_FILE% ^
    && ( echo vcdiff with missing delta file should fail, but succeeded ^
         &&exit /b 1 )
echo Test 11 ok

rem Test using -stats flag
%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
                -stats ^
    || ( echo Encode with -stats failed ^
         &&exit /b 1 )
%VCDIFF% -stats ^
         decode -dictionary %DICTIONARY_FILE% ^
                -delta %DELTA_FILE% ^
                -target %OUTPUT_TARGET_FILE% ^
    || ( echo Decode with -stats failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original ^
         &&exit /b 1 )
echo Test 13 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

rem open-vcdiff Issue 6
rem (https://github.com/google/open-vcdiff/issues/6)
rem Using empty file as dictionary should work, but (because dictionary is empty)
rem it will not produce a small delta file.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %EMPTY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -stats ^
    || ( echo vcdiff test with empty file as dictionary failed ^
         &&exit /b 1 )
echo Test 14 ok

del %DELTA_FILE%

rem Decode using something that isn't a delta file
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                -delta %DICTIONARY_FILE% ^
                -target %OUTPUT_TARGET_FILE% ^
    && ( echo vcdiff with invalid delta file should fail, but succeeded ^
         &&exit /b 1 )
echo Test 17 ok

%VCDIFF% %VCD_OPTIONS% ^
         encode -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
                -dictionary ^
    && ( echo -dictionary option with no file name should fail, but succeeded ^
         &&exit /b 1 )
echo Test 18 ok

%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -delta %DELTA_FILE% ^
                -target ^
    && ( echo -target option with no file name should fail, but succeeded ^
         &&exit /b 1 )
echo Test 19 ok

%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -target %TARGET_FILE% ^
                -delta ^
    && ( echo -delta option with no file name should fail, but succeeded ^
         &&exit /b 1 )
echo Test 20 ok

%VCDIFF% %VCD_OPTIONS% ^
         encode -dictionary %DICTIONARY_FILE% ^
                -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
                -buffersize ^
    && ( echo -buffersize option with no argument should fail, but succeeded ^
         &&exit /b 1 )
echo Test 21 ok

rem Using -buffersize=1 should still work.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -buffersize 1 ^
              -stats ^
    || ( echo vcdiff test with -buffersize=1 failed ^
         &&exit /b 1 )
echo Test 22 ok

del %DELTA_FILE%

rem Using -buffersize=1 with stdin/stdout means that vcdiff
rem will create a separate target window for each byte read.
%VCDIFF% encode -dictionary %DICTIONARY_FILE% ^
                -buffersize 1 ^
                -stats ^
                < %TARGET_FILE% ^
                > %DELTA_FILE% ^
    || ( echo Encode using stdin/stdout with -buffersize=1 failed ^
         &&exit /b 1 )
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                -buffersize 1 ^
                -stats ^
                < %DELTA_FILE% ^
                > %OUTPUT_TARGET_FILE% ^
    || ( echo Decode using stdin/stdout with -buffersize=1 failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original with -buffersize=1 ^
         &&exit /b 1 )
echo Test 23 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

rem Using -buffersize=0 should fail.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -buffersize 0 ^
    && ( echo vcdiff test with -buffersize=0 should fail, but succeeded ^
         &&exit /b 1 )
echo Test 24 ok

del %DELTA_FILE%

rem Using -buffersize=128M (larger than default maximum) should still work.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -buffersize 134217728 ^
              -stats ^
    || ( echo vcdiff test with -buffersize=128M failed ^
         &&exit /b 1 )
echo Test 25 ok

del %DELTA_FILE%

%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -froobish ^
    && ( echo vdiff test with unrecognized option should fail, but succeeded ^
         &&exit /b 1 )
echo Test 26 ok

%VCDIFF% %VCD_OPTIONS% ^
         encode -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
    && ( echo encode with no dictionary option should fail, but succeeded ^
         &&exit /b 1 )
echo Test 27 ok

%VCDIFF% decode -target %TARGET_FILE% ^
                -delta %DELTA_FILE% ^
    && ( echo decode with no dictionary option should fail, but succeeded ^
         &&exit /b 1 )
echo Test 28 ok

rem Remove -interleaved and -checksum options
%VCDIFF% encode -dictionary %DICTIONARY_FILE% ^
                < %TARGET_FILE% ^
                > %DELTA_FILE% ^
    || ( echo Encode without -interleaved and -checksum options failed ^
         &&exit /b 1 )
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                < %DELTA_FILE% ^
                > %OUTPUT_TARGET_FILE% ^
    || ( echo Decode non-interleaved output failed ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original with -interleaved ^
         &&exit /b 1 )
echo Test 29 ok

rem -target_matches option
%VCDIFF% encode -dictionary %DICTIONARY_FILE% ^
                -target_matches ^
                -stats ^
                < %TARGET_FILE% ^
                > %DELTA_FILE% ^
    || ( echo Encode with -target_matches option failed ^
         &&exit /b 1 )
rem The decode operation ignores the -target_matches option.
%VCDIFF% decode -dictionary %DICTIONARY_FILE% ^
                < %DELTA_FILE% ^
                > %OUTPUT_TARGET_FILE% ^
    || ( echo Decode output failed with -target_matches ^
         &&exit /b 1 )
fc /b %TARGET_FILE% %OUTPUT_TARGET_FILE% ^
    || ( echo Decoded target does not match original with -target_matches ^
         &&exit /b 1 )
echo Test 30 ok

del %DELTA_FILE%
del %OUTPUT_TARGET_FILE%

%VCDIFF% %VCD_OPTIONS% ^
         dencode -dictionary %DICTIONARY_FILE% ^
                 -target %TARGET_FILE% ^
                 -delta %DELTA_FILE% ^
    && ( echo vdiff with unrecognized action should fail, but succeeded ^
         &&exit /b 1 )
echo Test 31 ok

%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
    && ( echo vdiff test without delta option should fail, but succeeded ^
         &&exit /b 1 )
echo Test 32 ok

%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -delta %DELTA_FILE% ^
    && ( echo vdiff test without target option should fail, but succeeded ^
         &&exit /b 1 )
echo Test 33 ok

rem open-vcdiff Issue 8
rem (https://github.com/google/open-vcdiff/issues/8)
rem A malicious encoding that tries to produce a 4GB target file made up of 64
rem windows, each window having a size of 64MB.
%VCDIFF% %VCD_OPTIONS% ^
         decode -dictionary %DICTIONARY_FILE% ^
                -delta %MALICIOUS_ENCODING% ^
                -target %OUTPUT_TARGET_FILE% ^
                -max_target_file_size=65536 ^
    && ( echo Decoding malicious file should fail, but succeeded ^
         &&exit /b 1 )
echo Test 34 ok

del %OUTPUT_TARGET_FILE%

%VCDIFF% %VCD_OPTIONS% ^
         decode -dictionary %DICTIONARY_FILE% ^
                -delta %MALICIOUS_ENCODING% ^
                -target %OUTPUT_TARGET_FILE% ^
                -max_target_window_size=65536 ^
    && ( echo Decoding malicious file should fail, but succeeded ^
         &&exit /b 1 )
echo Test 35 ok

del %OUTPUT_TARGET_FILE%

rem Decoding a small target with the -max_target_file_size option should succeed.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -max_target_file_size=65536 ^
    || ( echo vcdiff test with -max_target_file_size failed ^
         &&exit /b 1 )
echo Test 36 ok

rem Decoding a small target with -max_target_window_size option should succeed.
%VCDIFF% %VCD_OPTIONS% ^
         test -dictionary %DICTIONARY_FILE% ^
              -target %TARGET_FILE% ^
              -delta %DELTA_FILE% ^
              -max_target_window_size=65536 ^
    || ( echo vcdiff test with -max_target_window_size failed ^
         &&exit /b 1 )
echo Test 37 ok

del %DELTA_FILE%

echo PASS
