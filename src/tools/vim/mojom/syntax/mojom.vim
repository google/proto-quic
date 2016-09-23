" Copyright 2015 The Chromium Authors. All rights reserved.
" Use of this source code is governed by a BSD-style license that can be
" found in the LICENSE file.

" Vim syntax file " Language: Mojom
" To get syntax highlighting for .mojom files, add the following to your .vimrc
" file:
"     set runtimepath^=/path/to/src/tools/vim/mojom

syn case match

syntax region mojomFold start="{" end="}" transparent fold

" keyword definitions
syntax keyword mojomType        bool int8 int16 int32 int64 uint8 uint16 uint32 uint64 float double array
syntax match mojomImport        "^\(import\)\s"
syntax keyword mojomKeyword     const module interface enum struct union
syntax match mojomOperator      /=>/
syntax match mojomOperator      /?/

" Comments
syntax keyword mojomTodo           contained TODO FIXME XXX
syntax region  mojomComment        start="/\*"  end="\*/" contains=mojomTodo,mojomDocLink,@Spell
syntax match   mojomLineComment    "//.*" contains=mojomTodo,@Spell
syntax match   mojomLineDocComment "///.*" contains=mojomTodo,mojomDocLink,@Spell
syntax region  mojomDocLink        contained start=+\[+ end=+\]+

" Strings
syn region mojomString start=+L\="+ skip=+\\\\\|\\"+ end=+"+ contains=@Spell
hi def link mojomString            String

" The default highlighting.
highlight default link mojomTodo            Todo
highlight default link mojomComment         Comment
highlight default link mojomLineComment     Comment
highlight default link mojomLineDocComment  Comment
highlight default link mojomDocLink         SpecialComment
highlight default link mojomType            Type
highlight default link mojomImport          Include
highlight default link mojomKeyword         Keyword
highlight default link mojomOperator        Operator

let b:current_syntax = "mojom"
let b:spell_options = "contained"

syn sync minlines=500

let b:current_syntax = "mojom"
