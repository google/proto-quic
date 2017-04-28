# Network Traffic Annotation Auditor
This script runs the clang tool for extraction of Network Traffic Annotations
from chromium source code and collects and summarizes its outputs.

## Running
1. `ninja -C [build directory] traffic_annotation_auditor`
2. Copy * from `[build_directory]/pyproto/tools/traffic_annotation` to
      `tools/traffic_annotation/auditor`

## Usage
`traffic_annotation_auditor.py [OPTION]... [path_filter]...`

Extracts network traffic annotations from source files. If path filter(s) are
specified, only those directories of the source will be analyzed.
Run `traffic_annotation_auditor.py --help` for options.

Example:
  `traffic_annotation_auditor.py --build-dir=out/Debug --summary-file=
  report.txt`


## Running on Windows
Before running the script as above, you should build COMPLETE chromium with
clang with keeprsp switch as follows:
1. `gn args [build_dir, e.g. out\Debug]`
2. add `is_clang=true` to the opened text file and save and close it.
3. `ninja -C [build_dir] -d keeprsp -k 1000`
