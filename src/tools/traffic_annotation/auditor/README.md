# Network Traffic Annotation Auditor
This executable runs the clang tool for extraction of Network Traffic
Annotations from chromium source code and collects and summarizes its outputs.

## Usage
`traffic_annotation_auditor [OPTION]... [path_filter]...`

Extracts network traffic annotations from source files. If path filter(s) are
specified, only those directories of the source will be analyzed.
Run `traffic_annotation_auditor --help` for options.

Example:
  `traffic_annotation_auditor --build-dir=out/Debug --summary-file=
  report.txt`

## Running on Linux
Before running the script as above, you should build the COMPLETE chromium.

## Running on Windows
Before running the script as above, you should build the COMPLETE chromium with
clang with keeprsp switch as follows:
1. `gn args [build_dir, e.g. out\Debug]`
2. add `is_clang=true` to the opened text file and save and close it.
3. `ninja -C [build_dir] -d keeprsp`
