# Traffic Annotation Extrator
This is a clang tool to extract network traffic annotations. The tool is run by
`tools/traffic_annotation/auditor/traffic_annotaion_auditor.py`. Refer to it for
help on how to use.

## Build on Linux
`tools/clang/scripts/update.py --bootstrap --force-local-build
   --without-android --extra-tools traffic_annotation_extractor`

## Build on Window
1. Either open a `VS2015 x64 Native Tools Command Prompt`, or open a normal
   command prompt and run `depot_tools\win_toolchain\vs_files\
   $long_autocompleted_hash\win_sdk\bin\setenv.cmd /x64`
2. Run `python tools/clang/scripts/update.py --bootstrap --force-local-build
   --without-android --extra-tools traffic_annotation_extractor`

## Usage
Run `traffic_annotation_extractor --help` for parameters help.
The executable extracts network traffic annotations from given file paths based
  on build parameters in build path, and writes them to llvm::outs.
  Each output will have the following format:
  - Line 1: File path.
  - Line 2: Name of the function in which annotation is defined.
  - Line 3: Line number of annotation.
  - Line 4: Unique id of annotation.
  - Line 5-: Serialized protobuf of the annotation.