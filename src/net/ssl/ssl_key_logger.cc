// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_key_logger.h"

#include <stdio.h>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/sequence_checker.h"
#include "base/sequenced_task_runner.h"

namespace net {

// An object which lives on the background SequencedTaskRunner and performs the
// blocking file operations.
class SSLKeyLogger::Core {
 public:
  Core() { sequence_checker_.DetachFromSequence(); }
  ~Core() { DCHECK(sequence_checker_.CalledOnValidSequence()); }

  void OpenFile(const base::FilePath& path) {
    DCHECK(sequence_checker_.CalledOnValidSequence());
    DCHECK(!file_);
    file_.reset(base::OpenFile(path, "a"));
    if (!file_)
      LOG(WARNING) << "Could not open " << path.value();
  }

  void WriteLine(const std::string& line) {
    DCHECK(sequence_checker_.CalledOnValidSequence());
    if (!file_)
      return;
    fprintf(file_.get(), "%s\n", line.c_str());
    fflush(file_.get());
  }

 private:
  base::ScopedFILE file_;
  base::SequenceChecker sequence_checker_;

  DISALLOW_COPY_AND_ASSIGN(Core);
};

SSLKeyLogger::SSLKeyLogger(
    const base::FilePath& path,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner)
    : task_runner_(task_runner), core_(new Core) {
  task_runner_->PostTask(
      FROM_HERE,
      base::Bind(&Core::OpenFile, base::Unretained(core_.get()), path));
}

SSLKeyLogger::~SSLKeyLogger() {
  task_runner_->DeleteSoon(FROM_HERE, core_.release());
}

void SSLKeyLogger::WriteLine(const std::string& line) {
  task_runner_->PostTask(
      FROM_HERE,
      base::Bind(&Core::WriteLine, base::Unretained(core_.get()), line));
}

}  // namespace net
