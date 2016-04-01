## Process this file with autoconf to produce configure.
## In general, the safest way to proceed is to run ./autogen.sh

# make sure we're interpreted by some minimal autoconf
AC_PREREQ(2.57)

AC_INIT(open-vcdiff, 0.8.4, opensource@google.com)
AC_CONFIG_SRCDIR(README)
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(src/config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AM_CONDITIONAL(GCC, test "$GCC" = yes)   # let the Makefile know if we're gcc
AC_CANONICAL_HOST

LT_INIT
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

# Check whether some low-level functions/files are available
AC_HEADER_STDC

# Built-in memcmp can be inefficient when gcc compiles for x86 or PowerPC
# processors.  In those cases, use an alternative function instead of memcmp.
case $host_cpu in
  *86*|powerpc*)
    if test "$GCC" = "yes"; then
      AC_DEFINE(VCDIFF_USE_BLOCK_COMPARE_WORDS, 1,
                Use custom compare function instead of memcmp)
    fi
    ;;
esac

AC_CHECK_HEADERS([ext/rope])
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([sys/mman.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([windows.h])
AC_CHECK_FUNCS([gettimeofday QueryPerformanceCounter])
AC_CHECK_FUNCS([memalign posix_memalign])
AC_CHECK_FUNCS([mprotect])

# Start of definitions needed by gflags package

# These are tested for by AC_HEADER_STDC, but I check again to set the var
AC_CHECK_HEADER(stdint.h, ac_cv_have_stdint_h=1, ac_cv_have_stdint_h=0)
AC_CHECK_HEADER(sys/types.h, ac_cv_have_systypes_h=1, ac_cv_have_systypes_h=0)
AC_CHECK_HEADER(inttypes.h, ac_cv_have_inttypes_h=1, ac_cv_have_inttypes_h=0)
AC_CHECK_HEADERS([fnmatch.h])

# These are the types I need.  We look for them in either stdint.h,
# sys/types.h, or inttypes.h, all of which are part of the default-includes.
AC_CHECK_TYPE(uint16_t, ac_cv_have_uint16_t=1, ac_cv_have_uint16_t=0)
AC_CHECK_TYPE(u_int16_t, ac_cv_have_u_int16_t=1, ac_cv_have_u_int16_t=0)
AC_CHECK_TYPE(__int16, ac_cv_have___int16=1, ac_cv_have___int16=0)

AC_CHECK_FUNCS([strtoll strtoq])
AC_CHECK_FUNCS([setenv putenv])    # MinGW has putenv but not setenv

AX_C___ATTRIBUTE__
# We only care about __attribute__ ((unused))
if test x"$ac_cv___attribute__" = x"yes"; then
  ac_cv___attribute__unused="__attribute__ ((unused))"
else
  ac_cv___attribute__unused=
fi

ACX_PTHREAD

# Find out what namespace 'normal' STL code lives in, and also what namespace
# the user wants our classes to be defined in
AC_CXX_STL_NAMESPACE
AC_DEFINE_GOOGLE_NAMESPACE(google)

# These are what's needed by gflags.h.in
AC_SUBST(ac_google_start_namespace)
AC_SUBST(ac_google_end_namespace)
AC_SUBST(ac_google_namespace)
AC_SUBST(ac_cv___attribute__unused)
AC_SUBST(ac_cv_have_stdint_h)
AC_SUBST(ac_cv_have_systypes_h)
AC_SUBST(ac_cv_have_inttypes_h)
AC_SUBST(ac_cv_have_uint16_t)
AC_SUBST(ac_cv_have_u_int16_t)
AC_SUBST(ac_cv_have___int16)

# For windows, this has a non-trivial value (__declspec(export)), but any
# system that uses configure wants this to be the empty string.
AC_DEFINE(GFLAGS_DLL_DECL,,
          [Always the empty-string on non-windows systems.
           On windows, should be "__declspec(dllexport)".
           This way, when we compile the dll, we export our functions/classes.
           It's safe to define this here because config.h is only used
           internally, to compile the DLL, and every DLL source file
           #includes "config.h" before anything else.])

# End of definitions needed by gflags package

# Solaris 10 6/06 has a bug where /usr/sfw/lib/libstdc++.la is empty.
# If so, we replace it with our own version.
LIBSTDCXX_LA_LINKER_FLAG=
if test -f /usr/sfw/lib/libstdc++.la && ! test -s /usr/sfw/lib/libstdc++.la
then
  LIBSTDCXX_LA_LINKER_FLAG='-L$(top_srcdir)/src/solaris'
fi
AC_SUBST(LIBSTDCXX_LA_LINKER_FLAG)

AC_CONFIG_FILES([Makefile
                 gflags/src/gflags/gflags.h
                 gflags/src/gflags/gflags_completions.h])
AC_OUTPUT
