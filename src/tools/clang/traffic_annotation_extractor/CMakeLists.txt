set(LLVM_LINK_COMPONENTS
  BitReader
  MCParser
  Option
  )

add_llvm_executable(traffic_annotation_extractor
  traffic_annotation_extractor.cpp
  )

target_link_libraries(traffic_annotation_extractor
  clangAST
  clangASTMatchers
  clangAnalysis
  clangBasic
  clangDriver
  clangEdit
  clangFrontend
  clangLex
  clangParse
  clangSema
  clangSerialization
  clangTooling
  )

cr_install(TARGETS traffic_annotation_extractor RUNTIME DESTINATION bin)
