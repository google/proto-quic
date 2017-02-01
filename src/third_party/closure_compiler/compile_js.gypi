# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
{
  'type': 'none',
  'variables': {
    'CLOSURE_DIR': '<(DEPTH)/third_party/closure_compiler',
    'EXTERNS_DIR': '<(CLOSURE_DIR)/externs',
    'includes': [
      'closure_args.gypi',
    ],
  },
  'actions': [
    {
      # This action optionally takes these arguments:
      # - source_files: a list of all of the source files to be compiled.
      #                 If source_files is not defined, |target_name| will be
      #                 used as the single source file.
      # - out_file: a file where the compiled output is written to. The default
      #             is gen/closure/<path to |target_name|>/|target_name|.js.
      # - depends: scripts that the source file(s) depends on being included
      #            already.
      # - externs: files that describe globals used the source file(s).
      # - script_args: additional arguments to pass to compile.py.
      # - closure_args: additional arguments to pass to the Closure compiler.
      # - closure_strictness_args: additional arguments dealing with the
      #                            strictness of compilation; Non-strict
      #                            defaults are provided that can be overriden.
      'action_name': 'compile_js',
      'variables': {
        'source_files%': ['<(_target_name).js'],
        'out_file%': '<(SHARED_INTERMEDIATE_DIR)/closure/<!(python <(CLOSURE_DIR)/build/outputs.py <(_target_name).js)',
        'externs%': [],
        'depends%': [],
        # TODO(dbeam): remove when no longer used from remoting/.
        'script_args%': [],
        'closure_args%': '<(default_closure_args)',
        'disabled_closure_args%': '<(default_disabled_closure_args)',
      },
      'inputs': [
        'compile_js.gypi',
        '<(CLOSURE_DIR)/compile.py',
        '<(CLOSURE_DIR)/processor.py',
        '<(CLOSURE_DIR)/build/inputs.py',
        '<(CLOSURE_DIR)/build/outputs.py',
        '<(CLOSURE_DIR)/compiler/compiler.jar',
        '<!@(python <(CLOSURE_DIR)/build/inputs.py <@(source_files) -d <@(depends) -e <@(externs))',
      ],
      'outputs': [
        '<(out_file)',
      ],
      'action': [
        'python',
        '<(CLOSURE_DIR)/compile.py',
        '<@(source_files)',
        '<@(script_args)',
        '--depends', '<@(depends)',
        '--externs', '<@(externs)',
        '--out_file', '<(out_file)',
        '--closure_args', '<@(closure_args)', '<@(disabled_closure_args)',
        # '--verbose' # for make glorious log spam of Closure compiler.
      ],
      'message': 'Compiling <(_target_name)',
    }
  ],
}
