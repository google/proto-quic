# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys


_HEADERS = """ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           ARM
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          52 (bytes into file)
  Start of section headers:          628588000 (bytes into file)
  Flags:                             0x5000200, Version5 EABI, soft-float ABI
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         9
  Size of section headers:           40 (bytes)
  Number of section headers:         40
  Section header string table index: 39
"""

_SECTIONS = """There are 40 section headers, starting at offset 0x25777de0:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000154 000154 000013 00   A  0   0  1
  [ 2] .note.gnu.build-id NOTE           00000168 000168 000024 00   A  0   0  4
  [ 3] .dynsym           DYNSYM          0000018c 00018c 001960 10   A  4   1  4
  [ 4] .dynstr           STRTAB          00001b0c 001b0c 000fb9 00   A  0   0  1
  [ 5] .hash             HASH            00002ad4 002ad4 000a7c 04   A  3   0  4
  [ 6] .gnu.version      VERSYM          00003558 003558 00032c 02   A  3   0  2
  [ 7] .gnu.version_d    VERDEF          00003888 003888 00001c 00   A  4   1  4
  [ 8] .gnu.version_r    VERNEED         000038a4 0038a4 000060 00   A  4   3  4
  [ 9] .rel.dyn          REL             00003904 003904 288498 08   A  3   0  4
  [10] .rel.plt          REL             0029fbec 29fbec 000b00 08   A  3   0  4
  [11] .plt              PROGBITS        002a06ec 2a06ec 001094 00  AX  0   0  4
  [12] .text             PROGBITS       002a1780 2a1780 223cd28 00  AX  0   0 64
  [13] .rodata           PROGBITS      02605000 2605000 5a72e4 00   A  0   0 256
  [14] .ARM.exidx        ARM_EXIDX      02bd3d10 2bd3d10 1771c8 08  AL 12   0  4
  [15] .ARM.extab        PROGBITS       02bd5858 2bd5858 02cd50 00   A  0   0  4
  [16] .data.rel.ro.local PROGBITS      02bdac40 2bd9c40 0c0e08 00  WA  0   0 16
  [17] .data.rel.ro      PROGBITS       02c9d420 2c9c420 104108 00  WA  0   0 16
  [18] .init_array       INIT_ARRAY     02da4680 2da3680 000008 00  WA  0   0  4
  [19] .fini_array       FINI_ARRAY     02da4774 2da3774 000008 00  WA  0   0  4
  [20] .dynamic          DYNAMIC        02da477c 2da377c 000130 08  WA  4   0  4
  [21] .got              PROGBITS       02da48b4 2da38b4 00a7cc 00  WA  0   0  4
  [22] .data             PROGBITS       02db0000 2daf000 018d88 00  WA  0   0 32
  [23] .bss              NOBITS         02dc8220 2dc7220 13d7e8 00  WA  0   0 32
  [35] .note.gnu.gold-version NOTE     00000000 226c41e8 00001c 00      0   0  4
  [36] .ARM.attributes  ARM_ATTRIBUTES 00000000 226c4204 00003c 00      0   0  1
  [37] .symtab           SYMTAB    00000000 226c4240 105ef20 10     38 901679  4
  [38] .strtab           STRTAB       00000000 23487ea0 213a4fe 00      0   0  1
  [39] .shstrtab         STRTAB        00000000 25777c2a 0001b4 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)
"""

_NOTES = """
Displaying notes found at file offset 0x00000168 with length 0x00000024:
  Owner                 Data size\tDescription
  GNU                   0x00000014\tNT_GNU_BUILD_ID (unique build ID bitstring)
    Build ID: WhatAnAmazingBuildId

Displaying notes found at file offset 0x226c41e8 with length 0x0000001c:
  Owner                 Data size\tDescription
  GNU                   0x00000009\tNT_GNU_GOLD_VERSION (gold version)
"""


def main():
  if sys.argv[1] == '-h':
    sys.stdout.write(_HEADERS)
  elif sys.argv[1] == '-S':
    sys.stdout.write(_SECTIONS)
  elif sys.argv[1] == '-n':
    sys.stdout.write(_NOTES)
  else:
    assert False, 'Invalid args: %s' % sys.argv


if __name__ == '__main__':
  main()
