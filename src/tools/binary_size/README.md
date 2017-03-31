# map2size.py

Parses a linker .map(.gz) file and outputs the result as a .size(.gz) file.

## Example Usage:

    # Android:
    gn gen out/Release --args='target_os="android" is_official_build=true'
    ninja -C out/Release -j 1000 libchrome.so
    tools/binary_size/map2size.py out/Release/lib.unstripped/libchrome.so.map.gz chrome.size -v
    # Linux:
    gn gen out/Release --args='is_official_build=true'
    ninja -C out/Release -j 1000 chrome
    tools/binary_size/map2size.py out/Release/chrome.map.gz chrome.size -v

# create_html_breakdown.py

Creates an interactive size breakdown as a stand-alone html report.

## Example Usage:

    tools/binary_size/create_html_breakdown.py chrome.size --report-dir size-report -v
    xdg-open size-report/index.html

# console.py

Starts a Python interpreter where you can run custom queries.

## Example Usage:

    # Runs a single diff and exits (does not enter interactive mode).
    tools/binary_size/console.py without_patch.size with_patch.size --query='Diff(size_info2, size_info1)'

    # Enters a Python REPL (it will print more guidance).
    tools/binary_size/console.py chrome.size

# Roadmap:

  Tracked in https://crbug.com/681694

  1. Better serialization format (finalize it before people start to use it).
      * Store only mangled names.
      * Save space by clustering by path (in addition to section_name).
  1. More console.py features:
      * Template Symbols - shows when templates lead to code bloat.
      * Duplicate Symbols - shows when statics in headers are an issue.
      * Overloaded Symbols - shows when overloads are excessive.
      * Per-class / namespace size (no way to distinguish class vs namespace).
      * Per-Chrome package (Chrome-specific grouping. e.g. name prefixes).
      * CSV output (for pasting into a spreadsheet).
  1. More create_html_breakdown.py features:
      * Convert paths from .o path to .cc path (better breakdowns).
        * Via "ninja -t commands libchrome.so" (3 seconds on my machine).
      * Break down by other groupings (e.g. create from nested `SymbolGroups`)
  1. More `map2size.py` features:
      * Find out more about 0xffffffffffffffff addresses, and why such large
        gaps exist after them.
      * Use nm to get the full list of symbols that share the same address.
  1. Integrate with `resource_sizes.py` so that it tracks size of major
     components separately: chrome vs blink vs skia vs v8.
  1. Speed up some steps (like normalizing names) via multiprocessing.
  1. Use resource whitelist information to attribute .pak file size to .o files.
