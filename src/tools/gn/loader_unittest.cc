// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/run_loop.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "tools/gn/build_settings.h"
#include "tools/gn/err.h"
#include "tools/gn/loader.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/parser.h"
#include "tools/gn/scheduler.h"
#include "tools/gn/tokenizer.h"

namespace {

class MockInputFileManager {
 public:
  typedef base::Callback<void(const ParseNode*)> Callback;

  MockInputFileManager() {
  }

  LoaderImpl::AsyncLoadFileCallback GetCallback();

  // Sets a given response for a given source file.
  void AddCannedResponse(const SourceFile& source_file,
                         const std::string& source);

  // Returns true if there is/are pending load(s) matching the given file(s).
  bool HasOnePending(const SourceFile& f) const;
  bool HasTwoPending(const SourceFile& f1, const SourceFile& f2) const;

  void IssueAllPending();

 private:
  struct CannedResult {
    std::unique_ptr<InputFile> input_file;
    std::vector<Token> tokens;
    std::unique_ptr<ParseNode> root;
  };

  bool AsyncLoadFile(const LocationRange& origin,
                     const BuildSettings* build_settings,
                     const SourceFile& file_name,
                     const Callback& callback,
                     Err* err) {
    pending_.push_back(std::make_pair(file_name, callback));
    return true;
  }

  typedef std::map<SourceFile, std::unique_ptr<CannedResult>> CannedResponseMap;
  CannedResponseMap canned_responses_;

  std::vector< std::pair<SourceFile, Callback> > pending_;
};

LoaderImpl::AsyncLoadFileCallback MockInputFileManager::GetCallback() {
  return base::Bind(&MockInputFileManager::AsyncLoadFile,
                    base::Unretained(this));
}

// Sets a given response for a given source file.
void MockInputFileManager::AddCannedResponse(const SourceFile& source_file,
                                             const std::string& source) {
  std::unique_ptr<CannedResult> canned(new CannedResult);
  canned->input_file.reset(new InputFile(source_file));
  canned->input_file->SetContents(source);

  // Tokenize.
  Err err;
  canned->tokens = Tokenizer::Tokenize(canned->input_file.get(), &err);
  EXPECT_FALSE(err.has_error());

  // Parse.
  canned->root = Parser::Parse(canned->tokens, &err);
  EXPECT_FALSE(err.has_error());

  canned_responses_[source_file] = std::move(canned);
}

bool MockInputFileManager::HasOnePending(const SourceFile& f) const {
  return pending_.size() == 1u && pending_[0].first == f;
}

bool MockInputFileManager::HasTwoPending(const SourceFile& f1,
                                         const SourceFile& f2) const {
  if (pending_.size() != 2u)
    return false;
  return pending_[0].first == f1 && pending_[1].first == f2;
}

void MockInputFileManager::IssueAllPending() {
  BlockNode block(BlockNode::DISCARDS_RESULT);  // Default response.

  for (const auto& cur : pending_) {
    CannedResponseMap::const_iterator found = canned_responses_.find(cur.first);
    if (found == canned_responses_.end())
      cur.second.Run(&block);
    else
      cur.second.Run(found->second->root.get());
  }
  pending_.clear();
}

// LoaderTest ------------------------------------------------------------------

class LoaderTest : public testing::Test {
 public:
  LoaderTest() {
    build_settings_.SetBuildDir(SourceDir("//out/Debug/"));
  }

 protected:
  Scheduler scheduler_;
  BuildSettings build_settings_;
  MockInputFileManager mock_ifm_;
};

}  // namespace

// -----------------------------------------------------------------------------

TEST_F(LoaderTest, Foo) {
  SourceFile build_config("//build/config/BUILDCONFIG.gn");
  build_settings_.set_build_config_file(build_config);

  scoped_refptr<LoaderImpl> loader(new LoaderImpl(&build_settings_));

  // The default toolchain needs to be set by the build config file.
  mock_ifm_.AddCannedResponse(build_config,
                              "set_default_toolchain(\"//tc:tc\")");

  loader->set_async_load_file(mock_ifm_.GetCallback());

  // Request the root build file be loaded. This should kick off the default
  // build config loading.
  SourceFile root_build("//BUILD.gn");
  loader->Load(root_build, LocationRange(), Label());
  EXPECT_TRUE(mock_ifm_.HasOnePending(build_config));

  // Completing the build config load should kick off the root build file load.
  mock_ifm_.IssueAllPending();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_ifm_.HasOnePending(root_build));

  // Load the root build file.
  mock_ifm_.IssueAllPending();
  base::RunLoop().RunUntilIdle();

  // Schedule some other file to load in another toolchain.
  Label second_tc(SourceDir("//tc2/"), "tc2");
  SourceFile second_file("//foo/BUILD.gn");
  loader->Load(second_file, LocationRange(), second_tc);
  EXPECT_TRUE(mock_ifm_.HasOnePending(SourceFile("//tc2/BUILD.gn")));

  // Running the toolchain file should schedule the build config file to load
  // for that toolchain.
  mock_ifm_.IssueAllPending();
  base::RunLoop().RunUntilIdle();

  // We have to tell it we have a toolchain definition now (normally the
  // builder would do this).
  const Settings* default_settings = loader->GetToolchainSettings(Label());
  Toolchain second_tc_object(default_settings, second_tc);
  loader->ToolchainLoaded(&second_tc_object);
  EXPECT_TRUE(mock_ifm_.HasOnePending(build_config));

  // Scheduling a second file to load in that toolchain should not make it
  // pending yet (it's waiting for the build config).
  SourceFile third_file("//bar/BUILD.gn");
  loader->Load(third_file, LocationRange(), second_tc);
  EXPECT_TRUE(mock_ifm_.HasOnePending(build_config));

  // Running the build config file should make our third file pending.
  mock_ifm_.IssueAllPending();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(mock_ifm_.HasTwoPending(second_file, third_file));

  EXPECT_FALSE(scheduler_.is_failed());
}
