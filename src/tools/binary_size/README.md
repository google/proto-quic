# Tools for Analyzing Chrome's Binary Size

These currently focus on Android and Linux platforms. However, some great tools
for Windows exist and are documented here:

 * https://www.chromium.org/developers/windows-binary-sizes

There is also a dedicated mailing-list for binary size discussions:

 * https://groups.google.com/a/chromium.org/forum/#!forum/binary-size

[TOC]

## diagnose_bloat.py

Determine the cause of binary size bloat between two commits. Works for Android
and Linux (although Linux symbol diffs have issues, as noted below).

### How it Works

1. Builds multiple revisions using release GN args.
   * Default is to build just two revisions (before & after commit)
   * Rather than building, can fetch build artifacts from perf bots (`--cloud`)
1. Measures all outputs using `resource_size.py` and `supersize`.
1. Saves & displays a breakdown of the difference in binary sizes.

### Example Usage

    # Build and diff HEAD^ and HEAD.
    tools/binary_size/diagnose_bloat.py HEAD -v

    # Diff BEFORE_REV and AFTER_REV using build artifacts downloaded from perf bots.
    tools/binary_size/diagnose_bloat.py AFTER_REV --reference-rev BEFORE_REV --cloud -v

    # Build and diff all contiguous revs in range BEFORE_REV..AFTER_REV for src/v8.
    tools/binary_size/diagnose_bloat.py AFTER_REV --reference-rev BEFORE_REV --subrepo v8 --all -v

    # Display detailed usage info (there are many options).
    tools/binary_size/diagnose_bloat.py -h

## Super Size

Collect, archive, and analyze Chrome's binary size.
Supports Android and Linux (although Linux
[has issues](https://bugs.chromium.org/p/chromium/issues/detail?id=717550)).

`.size` files are archived on perf builders so that regressions can be quickly
analyzed (via `diagnose_bloat.py --cloud`).

`.size` files are archived on official builders so that symbols can be diff'ed
between milestones.

### Technical Details

#### What's in a .size File?

`.size` files are gzipped plain text files that contain:

1. A list of .so section sizes, as reported by `readelf -S`,
1. Metadata (GN args, filenames, timestamps, git revision, build id),
1. A list of symbols, including name, address, size, and associated `.o` / `.cc`
   files.

#### How are Symbols Collected?

1. Symbol list is Extracted from linker `.map` file.
   * Map files contain some unique pieces of information, such as
     `** merge strings` entries, and the odd unnamed symbol (which map at least
     lists a `.o` path).
1. `.o` files are mapped to `.cc` files by parsing `.ninja` files.
   * This means that `.h` files are never listed as sources. No information about
     inlined symbols is gathered.
1. Symbol aliases (when multiple symbols share an address) are collected from
   debug information via `nm elf-file`.
   * Aliases have the same address and size, but report their `.pss` as
      `.size / .num_aliases`.
1. Paths for shared symbols (those found in multiple `.o` files) are collected
   by running `nm` on every `.o` file.
   * Shared symbols do not store the complete list of `.o` files. Instead, the
     common ancestor is computed and stored as the path (along with a
     `{shared}/count` suffix).

#### What Other Processing Happens?

1. Path normalization:
   * Prefixes are removed: `out/Release/`, `gen/`, `obj/`
   * Archive names made more pathy: `foo/bar.a(baz.o)` -> `foo/bar.a/baz.o`

1. Name normalization:
   * `(anonymous::)` is removed from names.
   * `vtable for FOO` -> `Foo [vtable]`
   * Names split into: `name`, `template_name`, `full_name`

1. Clustering
   * Compiler optimizations can cause a symbol to be broken into multiple
     smaller symbols. Clustering puts them back together.

1. Diffing
   * Some heuristics for matching up before/after symbols.

#### Is Super Size a Generic Tool?

No. Most of the logic is would could work for any ELF executable. However, being
a generic tool is not a goal. Some examples of existing Chrome-specific logic:

 * Assumes `.ninja` build rules are available.
 * Heuristic for locating `.so` given `.apk`.
 * Roadmap includes `.pak` file analysis.

### Usage: archive

Collect size information and dump it into a `.size` file.

*** note
**Note:** Refer to
[diagnose_bloat.py](https://cs.chromium.org/search/?q=file:diagnose_bloat.py+gn_args)
for list of GN args to build a Release binary.
***

Example:

    ninja -C out/Release -j 1000 apks/ChromePublic.apk
    tools/binary_size/supersize archive chrome.size --apk-file out/Release/apks/ChromePublic.apk -v

    # Linux:
    LLVM_DOWNLOAD_GOLD_PLUGIN=1 gclient runhooks  # One-time download.
    ninja -C out/Release -j 1000 chrome
    tools/binary_size/supersize archive chrome.size --elf-file out/Release/chrome -v

### Usage: html_report

Creates an interactive size breakdown (by source path) as a stand-alone html
report.

Example:

    tools/binary_size/supersize html_report chrome.size --report-dir size-report -v
    xdg-open size-report/index.html

### Usage: console

Starts a Python interpreter where you can run custom queries.

Example:

    # Prints size infomation and exits (does not enter interactive mode).
    tools/binary_size/supersize console chrome.size --query='Print(size_info)'

    # Enters a Python REPL (it will print more guidance).
    tools/binary_size/supersize console chrome.size

### Usage: diff

A convenience command equivalent to: `console before.size after.size --query='Print(Diff(size_info1, size_info2))'`

Example

    tools/binary_size/supersize diff before.size after.size --all

### Roadmap

Tracked in https://crbug.com/681694

1. [Better Linux support](https://bugs.chromium.org/p/chromium/issues/detail?id=717550) (clang+lld+lto vs gcc+gold).
1. More `archive` features:
    * Find out more about 0xffffffffffffffff addresses, and why such large
      gaps exist after them. ([crbug/709050](https://bugs.chromium.org/p/chromium/issues/detail?id=709050))
    * Collect .pak file information (using .o.whitelist files)
    * Collect java symbol information
    * Collect .apk entry information
1. More `console` features:
   * CSV output (for pasting into a spreadsheet).
   * Add `SplitByName()` - Like `GroupByName()`, but recursive.
   * A canned query, that does what ShowGlobals does (as described in [Windows Binary Sizes](https://www.chromium.org/developers/windows-binary-sizes)).
   * Show symbol counts by bucket size.
     * 3 symbols < 64 bytes. 10 symbols < 128, 3 < 256, 5 < 512, 0 < 1024, 3 < 2048
1. More `html_report` features:
   * Able to render size diffs (tint negative size red).
   * Break down by other groupings (Create from result of `SplitByName()`)
   * Render as simple tree view rather than 2d boxes
1. Integrate with `resource_sizes.py` so that it tracks size of major
   components separately: chrome vs blink vs skia vs v8.
1. Add dependency graph info, perhaps just on a per-file basis.
   * No idea how to do this, but Windows can do it via `tools\win\linker_verbose_tracking.py`
