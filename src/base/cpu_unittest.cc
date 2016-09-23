// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/cpu.h"
#include "build/build_config.h"

#include "testing/gtest/include/gtest/gtest.h"

#if _MSC_VER >= 1700
// C4752: found Intel(R) Advanced Vector Extensions; consider using /arch:AVX.
#pragma warning(disable: 4752)
#endif

// Tests whether we can run extended instructions represented by the CPU
// information. This test actually executes some extended instructions (such as
// MMX, SSE, etc.) supported by the CPU and sees we can run them without
// "undefined instruction" exceptions. That is, this test succeeds when this
// test finishes without a crash.
TEST(CPU, RunExtendedInstructions) {
#if defined(ARCH_CPU_X86_FAMILY)
  // Retrieve the CPU information.
  base::CPU cpu;

  ASSERT_TRUE(cpu.has_mmx());
  ASSERT_TRUE(cpu.has_sse());
  ASSERT_TRUE(cpu.has_sse2());

// GCC and clang instruction test.
#if defined(COMPILER_GCC)
  // Execute an MMX instruction.
  __asm__ __volatile__("emms\n" : : : "mm0");

  // Execute an SSE instruction.
  __asm__ __volatile__("xorps %%xmm0, %%xmm0\n" : : : "xmm0");

  // Execute an SSE 2 instruction.
  __asm__ __volatile__("psrldq $0, %%xmm0\n" : : : "xmm0");

  if (cpu.has_sse3()) {
    // Execute an SSE 3 instruction.
    __asm__ __volatile__("addsubpd %%xmm0, %%xmm0\n" : : : "xmm0");
  }

  if (cpu.has_ssse3()) {
    // Execute a Supplimental SSE 3 instruction.
    __asm__ __volatile__("psignb %%xmm0, %%xmm0\n" : : : "xmm0");
  }

  if (cpu.has_sse41()) {
    // Execute an SSE 4.1 instruction.
    __asm__ __volatile__("pmuldq %%xmm0, %%xmm0\n" : : : "xmm0");
  }

  if (cpu.has_sse42()) {
    // Execute an SSE 4.2 instruction.
    __asm__ __volatile__("crc32 %%eax, %%eax\n" : : : "eax");
  }

  if (cpu.has_avx()) {
    // Execute an AVX instruction.
    __asm__ __volatile__("vzeroupper\n" : : : "xmm0");
  }

  if (cpu.has_avx2()) {
    // Execute an AVX 2 instruction.
    __asm__ __volatile__("vpunpcklbw %%ymm0, %%ymm0, %%ymm0\n" : : : "xmm0");
  }

// Visual C 32 bit and ClangCL 32/64 bit test.
#elif defined(COMPILER_MSVC) && (defined(ARCH_CPU_32_BITS) || \
      (defined(ARCH_CPU_64_BITS) && defined(__clang__)))

  // Execute an MMX instruction.
  __asm emms;

  // Execute an SSE instruction.
  __asm xorps xmm0, xmm0;

  // Execute an SSE 2 instruction.
  __asm psrldq xmm0, 0;

  if (cpu.has_sse3()) {
    // Execute an SSE 3 instruction.
    __asm addsubpd xmm0, xmm0;
  }

  if (cpu.has_ssse3()) {
    // Execute a Supplimental SSE 3 instruction.
    __asm psignb xmm0, xmm0;
  }

  if (cpu.has_sse41()) {
    // Execute an SSE 4.1 instruction.
    __asm pmuldq xmm0, xmm0;
  }

  if (cpu.has_sse42()) {
    // Execute an SSE 4.2 instruction.
    __asm crc32 eax, eax;
  }

// Visual C 2012 required for AVX.
#if _MSC_VER >= 1700
  if (cpu.has_avx()) {
    // Execute an AVX instruction.
    __asm vzeroupper;
  }

  if (cpu.has_avx2()) {
    // Execute an AVX 2 instruction.
    __asm vpunpcklbw ymm0, ymm0, ymm0
  }
#endif  // _MSC_VER >= 1700
#endif  // defined(COMPILER_GCC)
#endif  // defined(ARCH_CPU_X86_FAMILY)
}
