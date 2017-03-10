# run_binary_size_analysis.py

## About:
  * Uses `nm --print-size` and `addr2line` to extract size information
    * nm's correctness can be somewhat suspect at times...
  * Produces an html report with bloat grouped by source path.
  * Produces an "nm"-formatted dump of symbols with their sources resolved by
    addr2line.
  * For Chrome, takes ~60 minutes on a z620, but --jobs=10 reduces to ~5 minutes
    (**at the cost of 60GB of RAM**).

## Example Usage:

    ninja -C out/Release -j 1000 libchrome.so
    tools/binary_size/run_binary_size_analysis.py \
        --library out/Release/lib.unstripped/libchrome.so \
        --destdir out/Release/binary-size-report \
        --jobs=10
    xdg-open out/Release/binary-size-report/index.html

## Recommanded GN Args:

    is_official_build = true
    # There's not much point in measuring size without this flag :).

## Optional GN Args:

     is_clang = true
     # Anecdotally produces more stable symbol names over time.
     enable_profiling = true
     # Anecdotally makes symbol lookup more accurate.
     enable_full_stack_frames_for_profiling = true
     # With enable_profiling, further improves symbol lookup accuracy but
     # will completely disable inlining, decreasing spatial accuracy.

# explain_binary_size_delta.py

Prints a delta of two "nm"-formatted outputs from `run_binary_size_analysis.py`.

## Example Usage:

    tools/binary_size/explain_binary_size_delta.py \
        --nm1 out/Release/size-report1/nm.out \
        --nm2 out/Release/size-report2/nm.out \
        --showsouces --showsymbols # Optional

# Open Issues

Use Monorail label [Tools-BinarySize](https://code.google.com/p/chromium/issues/list?can=2&q=label:Tools-BinarySize).
