================================================================================
              __________  .__
              \______   \ |__|   ____   _____    _______   ___.__.
               |    |  _/ |  |  /    \  \__  \   \_  __ \ <   |  |
               |    |   \ |  | |   |  \  / __ \_  |  | \/  \___  |
               |______  / |__| |___|  / (____  /  |__|     / ____|
                      \/            \/       \/            \/
    _________ .__                        ___________                   .__
   /   _____/ |__| ________   ____       \__    ___/   ____     ____   |  |
   \_____  \  |  | \___   / _/ __ \        |    |     /  _ \   /  _ \  |  |
   /        \ |  |  /    /  \  ___/        |    |    (  <_> ) (  <_> ) |  |__
  /_______  / |__| /_____ \  \___  >       |____|     \____/   \____/  |____/
          \/             \/      \/
================================================================================

--------------------------------------------------------------------------------
Introduction
--------------------------------------------------------------------------------
The ever-increasing size of binaries is a problem for everybody. Increased
binary size means longer download times and a bigger on-disk footprint after
installation. Mobile devices suffer the worst, as they frequently have
sub-optimal connectivity and limited storage capacity. Developers currently
have almost no visibility into how the space in the existing binaries is
divided nor how their contributions change the space within those binaries.
The first step to reducing the size of binaries is to make the size information
accessible to everyone so that developers can take action.

There are two parts to the Binary Size Tool:
1. run_binary_size_analysis.py
   This script will produce a detailed breakdown of a binary, including an HTML
   report and (optionally) a detailed ""nm"-formatted dump of all the symbols
   with their sources resolved by addr2line. This tool is great for finding the
   bloat in binaries.

2. explain_binary_size_delta.py
   This script takes the "nm"-formatted input from two runs of the first tool
   (run_binary_size_analysis.py) and produces a detailed breakdown of how the
   symbols have changed between the two binaries that were originally analyzed.
   The breakdown shows the size changes of symbols as well as which symbols have
   been added, removed, or changed. This tool is great for thoroughly
   characterizing the size change resulting from a code change.

   Because this tool relies solely upon the "nm" output from
   run_binary_size_analysis.py, it can be run at any time even if the source
   code described by the "nm" output is no longer available. It is also much
   faster than run_binary_size_analysis.py, typically completing in a few
   seconds for even very large binaries.

--------------------------------------------------------------------------------
How to Run: run_binary_size_analysis.py
--------------------------------------------------------------------------------
Running the tool is fairly simple. For the sake of this example we will
pretend that you are building the Content Shell APK for Android.

  1. Build your product as you normally would*, e.g.:
       ninja -C out/Release -j 100 content_shell_apk

     * For results that are as spatially accurate as possible, you should always
     build with a Release configuration so that the end product is as close to
     the real thing as possible. However, it can sometimes be useful to improve
     consistency and accuracy of symbol lookup even if it perturbs the overall
     accuracy of the tool. Consider adding these GN args:
       is_clang = true
         Anecdotally produces more stable symbol names over time.
       enable_profiling = true
         Anecdotally makes symbol lookup more accurate (note that it
         doesn't work with clang on ARM/Android builds, see
         https://crbug.com/417323 for more information.
       enable_full_stack_frames_for_profiling = true
         With enable_profiling, further improves symbol lookup accuracy but
         will completely disable inlining, decreasing spatial accuracy.

  2. Run the tool specifying the library and the output report directory.
     This command will run the analysis on the Content Shell native library for
     Android, producing an HTML report in /tmp/report and saving the NM output
     (useful for re-running the tool or analyzing deltas between two builds)
     under /tmp/report/nm.out:
       tools/binary_size/run_binary_size_analysis.py \
         --library out/Release/lib.unstripped/libcontent_shell_content_view.so \
         --destdir /tmp/report

Of course, there are additional options that you can see by running the tool
with "--help".

This whole process takes about an hour on a modern (circa 2014) machine. If you
have LOTS of RAM, you can use the "--jobs" argument to add more addr2line
workers; doing so will *greatly* reduce the processing time but will devour
system memory. If you've got the horsepower, 10 workers can thrash through the
binary in about 5 minutes at a cost of around 60 GB of RAM. The default number
of jobs is 1. Patches to job number auto-selection are welcome!

When the tool finishes its work you'll find an HTML report in the output
directory that you specified with "--destdir". Open the index.html file in your
*cough* browser of choice *cough* and have a look around. The index.html page
is likely to evolve over time, but will always be your starting point for
investigation. From here you'll find links to various views of the data such
as treemap visualizations, overall statistics and "top n" lists of various
kinds.

The report is completely standalone. No external resources are required, so the
report may be saved and viewed offline with no problems.

--------------------------------------------------------------------------------
How to Run: explain_binary_size_delta.py
--------------------------------------------------------------------------------
Continuing the example, assume that run_binary_size_analysis.py has been run
both before and after a code change and that the "nm.out" files have been saved
to "nm.out.before" and "nm.out.after". To generate an explanation of the symbol
differences between the two runs:

  tools/binary_size/explain_binary_size_delta.py \
  --nm1 nm.out.before --nm2 nm.out.after

This will output a concise summary of the symbol changes between the two
libraries. Much more information is available by specifying flags like
"--showsources" and (for the comprehensive answer) "--showsymbols". Use "--help"
for a full list of options.

Unlike run_binary_size_analysis.py, this tool doesn't (yet) produce any kind of
HTML report. Contributions are welcome.

--------------------------------------------------------------------------------
Caveats
--------------------------------------------------------------------------------
The tool is not perfect and has several shortcomings:

  * Not all space in the binary is accounted for. The causes are still under
    investigation, but there are of course sections in the binary that do not
    contain symbol information, etceteras. The vast majority of the binary is
    generally symbols, though, so the discrepancy should be very small.
  * When dealing with inlining and such, the size cost is attributed to the
    resource in which the code gets inlined. Depending upon your goals for
    analysis, this may be either good or bad; fundamentally, the more trickery
    that the compiler and/or linker do, the less simple the relationship
    between the original source and the resultant binary.
  * The Javascript code in the HTML report assumes code lives in Chromium for
    generated hyperlinks and will not hyperlink any file that starts with the
    substring "out".
  * There is as yet no way to configure project-specific bindings for symbols/
    source files to locations on disk. Such configuration would be useful for
    manually deduping and disambiguating results. Some day, hopefully, this will
    be supported.

--------------------------------------------------------------------------------
Feature Requests and Bug Reports
--------------------------------------------------------------------------------
Please file bugs and feature requests here, making sure to use the label
"Tools-BinarySize":
  https://code.google.com/p/chromium/issues/entry?labels=Tools-BinarySize

View all open issues here:
  https://code.google.com/p/chromium/issues/list?can=2&q=label:Tools-BinarySize
