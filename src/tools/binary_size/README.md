# analyze.py

Parses and processes a linker .map file and outputs the result as a .size file.

## Example Usage:

    # Android:
    gn gen out/Release --args='target_os="android" is_official_build=true'
    ninja -C out/Release -j 1000 libchrome.so
    tools/binary_size/analyze.py out/Release/lib.unstripped/libchrome.so.map.gz --output chrome.size -v
    # Linux:
    gn gen out/Release --args='is_official_build=true'
    ninja -C out/Release -j 1000 chrome
    tools/binary_size/analyze.py out/Release/chrome.map.gz --output chrome.size -v

# create_html_breakdown.py

Creates an interactive size breakdown as a stand-alone html report.

## Example Usage:

    tools/binary_size/create_html_breakdown.py chrome.size --report-dir size-report -v
    xdg-open size-report/index.html

# query.py

Starts a Python interpreter where you can run custom queries.

## Example Usage:

    # Run a single query and exit rather than entering interactive mode:
    tools/binary_size/query.py chrome.size --query 'all_syms.WhereBiggerThan(1000)'

    # Enters a Python REPL:
    tools/binary_size/query.py chrome.size

# Roadmap:

  Tracked in https://crbug.com/681694

  1. Convert explain_binary_size_delta.py to use new data model.
  1. More query.py features:
      * Template Symbols - shows when templates lead to code bloat.
      * Duplicate Symbols - shows when statics in headers are an issue.
      * Overloaded Symbols - shows when overloads are excessive.
      * Per-class / namespace size (no way to distinguish class vs namespace).
      * Per-Chrome package (Chrome-specific grouping. e.g. name prefixes).
      * An interactive UI (either drop into python or use a web server).
  1. More create_html_breakdown.py features:
      * Convert paths from .o path to .cc path (better breakdowns).
      * Break down by query.py groupings (use query.py to define GroupBy()s,
        then render to html graph)
  1. More analysis.py features:
      * Find out more about 0xffffffffffffffff addresses, and why such large
        gaps exist after them.
      * Use nm to get the full list of symbols that share the same address.
  1. Integrate with `resource_sizes.py` so that it tracks size of major
     components separately: chrome vs blink vs skia vs v8.
  1. Speed up some steps (like normalizing names) via multiprocessing.
  1. Use resource whitelist information to attribute .pak file size to .o files.
