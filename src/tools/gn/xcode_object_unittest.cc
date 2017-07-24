// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/xcode_object.h"

#include "base/memory/ptr_util.h"
#include "testing/gtest/include/gtest/gtest.h"

// Tests that instantiating Xcode objects doesn't crash.
TEST(XcodeObject, InstantiatePBXSourcesBuildPhase) {
  PBXSourcesBuildPhase pbx_sources_build_phase;
}

TEST(XcodeObject, InstantiatePBXFrameworksBuildPhase) {
  PBXFrameworksBuildPhase pbx_frameworks_build_phase;
}

TEST(XcodeObject, InstantiatePBXShellScriptBuildPhase) {
  PBXShellScriptBuildPhase pbx_shell_script_build_phase("name", "shell_script");
}

TEST(XcodeObject, InstantiatePBXGroup) {
  PBXGroup pbx_group("/dir1/dir2", "group");
}

TEST(XcodeObject, InstantiatePBXProject) {
  PBXProject pbx_project("project", "config", "out/build", PBXAttributes());
}

TEST(XcodeObject, InstantiatePBXFileReference) {
  PBXFileReference pbx_file_reference("test.cc", "sources/tools/test.cc",
                                      "sourcecode.cpp.cpp");
}

TEST(XcodeObject, InstantiatePBXBuildFile) {
  PBXFileReference pbx_file_reference("test.cc", "sources/tools/test.cc",
                                      "sourcecode.cpp.cpp");
  PBXSourcesBuildPhase pbx_sources_build_phase;
  PBXBuildFile pbx_build_file(&pbx_file_reference, &pbx_sources_build_phase,
                              CompilerFlags::NONE);
}

TEST(XcodeObject, InstantiatePBXAggregateTarget) {
  PBXAggregateTarget pbx_aggregate_target("target_name", "shell_script",
                                          "config_name", PBXAttributes());
}

TEST(XcodeObject, InstantiatePBXNativeTarget) {
  PBXFileReference product_reference("product.app", "product.app",
                                     "wrapper.application");
  PBXNativeTarget pbx_native_target(
      "target_name", "ninja gn_unittests", "config_name", PBXAttributes(),
      "com.apple.product-type.application", "product_name", &product_reference);
}

TEST(XcodeObject, InstantiatePBXContainerItemProxy) {
  PBXProject pbx_project("project_name", "config_name", "out/build",
                         PBXAttributes());
  PBXFileReference product_reference("product.app", "product.app",
                                     "wrapper.application");
  PBXNativeTarget pbx_native_target(
      "target_name", "ninja gn_unittests", "config_name", PBXAttributes(),
      "com.apple.product-type.application", "product_name", &product_reference);
  PBXContainerItemProxy pbx_container_item_proxy(&pbx_project,
                                                 &pbx_native_target);
}

TEST(XcodeObject, InstantiatePBXTargetDependency) {
  PBXProject pbx_project("project_name", "config_name", "out/build",
                         PBXAttributes());
  PBXFileReference product_reference("product.app", "product.app",
                                     "wrapper.application");
  PBXNativeTarget pbx_native_target(
      "target_name", "ninja gn_unittests", "config_name", PBXAttributes(),
      "com.apple.product-type.application", "product_name", &product_reference);
  PBXTargetDependency pbx_target_dependency(
      &pbx_native_target, base::MakeUnique<PBXContainerItemProxy>(
                              &pbx_project, &pbx_native_target));
}

TEST(XcodeObject, InstantiateXCBuildConfiguration) {
  XCBuildConfiguration xc_build_configuration("config_name", PBXAttributes());
}

TEST(XcodeObject, InstantiateXCConfigurationList) {
  PBXFileReference product_reference("product.app", "product.app",
                                     "wrapper.application");
  PBXNativeTarget pbx_native_target(
      "target_name", "ninja gn_unittests", "config_name", PBXAttributes(),
      "com.apple.product-type.application", "product_name", &product_reference);
  XCConfigurationList xc_xcconfiguration_list(
      "config_list_name", PBXAttributes(), &pbx_native_target);
}
