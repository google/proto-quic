// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "tools/gn/analyzer.h"
#include "tools/gn/build_settings.h"
#include "tools/gn/builder.h"
#include "tools/gn/loader.h"
#include "tools/gn/settings.h"
#include "tools/gn/source_file.h"


namespace {

class MockLoader : public Loader {
 public:
  MockLoader() {}

  void Load(const SourceFile& file,
            const LocationRange& origin,
            const Label& toolchain_name) override {}
  void ToolchainLoaded(const Toolchain* toolchain) override {}
  Label GetDefaultToolchain() const override {
    return Label(SourceDir("//tc/"), "default");
  }
  const Settings* GetToolchainSettings(const Label& label) const override {
    return nullptr;
  }

 private:
  ~MockLoader() override {}
};

class AnalyzerTest : public testing::Test {
 public:
  AnalyzerTest()
      : loader_(new MockLoader),
        builder_(loader_.get()),
        settings_(&build_settings_, std::string()) {
    build_settings_.SetBuildDir(SourceDir("//out/"));
    settings_.set_toolchain_label(Label(SourceDir("//tc/"), "default"));
    settings_.set_default_toolchain_label(settings_.toolchain_label());
    tc_dir_ = settings_.toolchain_label().dir();
    tc_name_ = settings_.toolchain_label().name();
  }

  Target* MakeTarget(const std::string dir,
                     const std::string name,
                     Target::OutputType type,
                     const std::vector<std::string>& sources,
                     const std::vector<Target*>& deps) {
    Label lbl(SourceDir(dir), name, tc_dir_, tc_name_);
    Target* target = new Target(&settings_, lbl);
    target->set_output_type(type);
    for (const auto& s : sources)
      target->sources().push_back(SourceFile(s));
    for (const auto* d : deps)
      target->public_deps().push_back(LabelTargetPair(d));
    builder_.ItemDefined(std::unique_ptr<Item>(target));
    return target;
  }

  void AddSource(Target* a, std::string path) {}

  void AddDep(Target* a, Target* b) {}

  void SetUpABasicBuildGraph() {
    std::vector<std::string> no_sources;
    std::vector<Target*> no_deps;

    // All of the targets below are owned by the builder, so none of them
    // get leaked.

    // Ignore the returned target since nothing depends on it.
    MakeTarget("//", "a", Target::EXECUTABLE, {"//a.cc"}, no_deps);

    Target* b =
        MakeTarget("//d", "b", Target::SOURCE_SET, {"//d/b.cc"}, no_deps);

    Target* b_unittests = MakeTarget("//d", "b_unittests", Target::EXECUTABLE,
                                     {"//d/b_unittest.cc"}, {b});

    Target* c = MakeTarget("//d", "c", Target::EXECUTABLE, {"//d/c.cc"}, {b});

    Target* b_unittests_and_c =
        MakeTarget("//d", "b_unittests_and_c", Target::GROUP, no_sources,
                   {b_unittests, c});

    Target* e =
        MakeTarget("//d", "e", Target::EXECUTABLE, {"//d/e.cc"}, no_deps);

    // Also ignore this returned target since nothing depends on it.
    MakeTarget("//d", "d", Target::GROUP, no_sources, {b_unittests_and_c, e});
  }

  void RunBasicTest(const std::string& input,
                    const std::string& expected_output) {
    SetUpABasicBuildGraph();
    Err err;
    std::string actual_output = Analyzer(builder_).Analyze(input, &err);
    EXPECT_EQ(err.has_error(), false);
    EXPECT_EQ(expected_output, actual_output);
  }

 protected:
  scoped_refptr<MockLoader> loader_;
  Builder builder_;
  BuildSettings build_settings_;
  Settings settings_;
  SourceDir tc_dir_;
  std::string tc_name_;
};

}  // namespace

// TODO: clean this up when raw string literals are allowed.

TEST_F(AnalyzerTest, AllWasPruned) {
  RunBasicTest(
      "{"
      "  \"files\": [ \"//d/b.cc\" ],"
      "  \"additional_compile_targets\": [ \"all\" ],"
      "  \"test_targets\": [ ]"
      "}",
      "{"
      "\"compile_targets\":[\"//d:b_unittests\",\"//d:c\"],"
      "\"status\":\"Found dependency\","
      "\"test_targets\":[]"
      "}");
}

TEST_F(AnalyzerTest, NoDependency) {
  RunBasicTest(
      "{"
      "  \"files\":[ \"//missing.cc\" ],"
      "  \"additional_compile_targets\": [ \"all\" ],"
      "  \"test_targets\": [ \"//:a\" ]"
      "}",
      "{"
      "\"compile_targets\":[],"
      "\"status\":\"No dependency\","
      "\"test_targets\":[]"
      "}");
}

TEST_F(AnalyzerTest, NoFilesNoTargets) {
  RunBasicTest(
      "{"
      "  \"files\": [],"
      "  \"additional_compile_targets\": [],"
      "  \"test_targets\": []"
      "}",
      "{"
      "\"compile_targets\":[],"
      "\"status\":\"No dependency\","
      "\"test_targets\":[]"
      "}");
}

TEST_F(AnalyzerTest, OneTestTargetModified) {
  RunBasicTest(
      "{"
      "  \"files\": [ \"//a.cc\" ],"
      "  \"additional_compile_targets\": [],"
      "  \"test_targets\": [ \"//:a\" ]"
      "}",
      "{"
      "\"compile_targets\":[],"
      "\"status\":\"Found dependency\","
      "\"test_targets\":[\"//:a\"]"
      "}");
}

TEST_F(AnalyzerTest, FilesArentSourceAbsolute) {
  RunBasicTest(
      "{"
      "  \"files\": [ \"a.cc\" ],"
      "  \"additional_compile_targets\": [],"
      "  \"test_targets\": [ \"//:a\" ]"
      "}",
      "{"
      "\"error\":"
      "\"\\\"a.cc\\\" is not a source-absolute or absolute path.\","
      "\"invalid_targets\":[]"
      "}");
}

TEST_F(AnalyzerTest, WrongInputFields) {
  RunBasicTest(
      "{"
      "  \"files\": [ \"//a.cc\" ],"
      "  \"compile_targets\": [],"
      "  \"test_targets\": [ \"//:a\" ]"
      "}",
      "{"
      "\"error\":"
      "\"Input does not have a key named "
      "\\\"additional_compile_targets\\\" with a list value.\","
      "\"invalid_targets\":[]"
      "}");
}

TEST_F(AnalyzerTest, BuildFilesWereModified) {
  // This tests that if a build file is modified, we bail out early with
  // "Found dependency (all)" error since we can't handle changes to
  // build files yet (crbug.com/555273).
  RunBasicTest(
      "{"
      "  \"files\": [ \"//a.cc\", \"//BUILD.gn\" ],"
      "  \"additional_compile_targets\": [],"
      "  \"test_targets\": [ \"//:a\" ]"
      "}",
      "{"
      "\"compile_targets\":[\"//:a\"],"
      "\"status\":\"Found dependency (all)\","
      "\"test_targets\":[\"//:a\"]"
      "}");
}

TEST_F(AnalyzerTest, BuildFilesWereModifiedAndCompilingAll) {
  // This tests that if a build file is modified, we bail out early with
  // "Found dependency (all)" error since we can't handle changes to
  // build files yet (crbug.com/555273).
  RunBasicTest(
      "{"
      "  \"files\": [ \"//a.cc\", \"//BUILD.gn\" ],"
      "  \"additional_compile_targets\": [ \"all\" ],"
      "  \"test_targets\": [ \"//:a\" ]"
      "}",
      "{"
      "\"compile_targets\":[\"all\"],"
      "\"status\":\"Found dependency (all)\","
      "\"test_targets\":[\"//:a\"]"
      "}");
}
