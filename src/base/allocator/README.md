This document describes how malloc / new calls are routed in the various Chrome
platforms.

Bare in mind that the chromium codebase does not always just use `malloc()`.
Some examples:
 - Large parts of the renderer (Blink) use two home-brewed allocators,
   PartitionAlloc and BlinkGC (Oilpan).
 - Some subsystems, such as the V8 JavaScript engine, handle memory management
   autonomously.
 - Various parts of the codebase use abstractions such as `SharedMemory` or
   `DiscardableMemory` which, similarly to the above, have their own page-level
   memory management.

Background
----------
The `allocator` target defines at compile-time the platform-specific choice of
the allocator and extra-hooks which services calls to malloc/new. The relevant
build-time flags involved are `use_allocator` and `win_use_allocator_shim`.

The default choices are as follows:

**Windows**  
`use_allocator: winheap`, the default Windows heap.
Additionally, `static_library` (i.e. non-component) builds have a shim
layer wrapping malloc/new, which is controlled by `win_use_allocator_shim`.  
The shim layer provides extra security features, such as preventing large
allocations that can hit signed vs. unsigned bugs in third_party code.

**Linux Desktop / CrOS**  
`use_allocator: tcmalloc`, a forked copy of tcmalloc which resides in
`third_party/tcmalloc/chromium`. Setting `use_allocator: none` causes the build
to fall back to the system (Glibc) symbols.

**Android**  
`use_allocator: none`, always use the allocator symbols coming from Android's
libc (Bionic). As it is developed as part of the OS, it is considered to be
optimized for small devices and more memory-efficient than other choices.  
The actual implementation backing malloc symbols in Bionic is up to the board
config and can vary (typically *dlmalloc* or *jemalloc* on most Nexus devices).

**Mac/iOS**  
`use_allocator: none`, we always use the system's allocator implementation.

In addition, when building for `asan` / `msan` / `syzyasan` `valgrind`, the
both the allocator and the shim layer are disabled.

Layering and build deps
-----------------------
The `allocator` target provides both the source files for tcmalloc (where
applicable) and the linker flags required for the Windows shim layer.
The `base` target is (almost) the only one depending on `allocator`. No other
targets should depend on it, with the exception of the very few executables /
dynamic libraries that don't depend, either directly or indirectly, on `base`
within the scope of a linker unit.

More importantly, **no other place outside of `/base` should depend on the
specific allocator** (e.g., directly include `third_party/tcmalloc`).
If such a functional dependency is required that should be achieved using
abstractions in `base` (see `/base/allocator/allocator_extension.h` and
`/base/memory/`)

**Why `base` depends on `allocator`?**  
Because it needs to provide services that depend on the actual allocator
implementation. In the past `base` used to pretend to be allocator-agnostic
and get the dependencies injected by other layers. This ended up being an
inconsistent mess.
See the [allocator cleanup doc][url-allocator-cleanup] for more context.

Linker unit targets (executables and shared libraries) that depend in some way
on `base` (most of the targets in the codebase) get automatically the correct
set of linker flags to pull in tcmalloc or the Windows shim-layer.


Source code
-----------
This directory contains just the allocator (i.e. shim) layer that switches
between the different underlying memory allocation implementations.

The tcmalloc library originates outside of Chromium and exists in
`../../third_party/tcmalloc` (currently, the actual location is defined in the
allocator.gyp file). The third party sources use a vendor-branch SCM pattern to
track Chromium-specific changes independently from upstream changes.

The general intent is to push local changes upstream so that over
time we no longer need any forked files.


Appendixes
----------
**How does the Windows shim layer replace the malloc symbols?**  
The mechanism for hooking LIBCMT in Windows is rather tricky.  The core
problem is that by default, the Windows library does not declare malloc and
free as weak symbols.  Because of this, they cannot be overridden.  To work
around this, we start with the LIBCMT.LIB, and manually remove all allocator
related functions from it using the visual studio library tool.  Once removed,
we can now link against the library and provide custom versions of the
allocator related functionality.
See the script `preb_libc.py` in this folder.

Related links
-------------
- [Allocator Cleanup Doc - Jan 2016][url-allocator-cleanup]
- [Proposal to use PartitionAlloc as default allocator](https://crbug.com/339604)
- [Memory-Infra: Tools to profile memory usage in Chrome](components/tracing/docs/memory_infra.md)

[url-allocator-cleanup]: https://docs.google.com/document/d/1V77Kgp_4tfaaWPEZVxNevoD02wXiatnAv7Ssgr0hmjg/edit?usp=sharing
