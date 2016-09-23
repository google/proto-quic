// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SQL_SQL_MEMORY_DUMP_PROVIDER_H
#define SQL_SQL_MEMORY_DUMP_PROVIDER_H

#include "base/macros.h"
#include "base/memory/singleton.h"
#include "base/trace_event/memory_dump_provider.h"
#include "sql/sql_export.h"

namespace sql {

// Adds process-wide memory usage statistics about sqlite to chrome://tracing.
// sql::Connection::OnMemoryDump adds per-connection memory statistics.
class SQL_EXPORT SqlMemoryDumpProvider
    : public base::trace_event::MemoryDumpProvider {
 public:
  static SqlMemoryDumpProvider* GetInstance();

  // MemoryDumpProvider implementation.
  bool OnMemoryDump(const base::trace_event::MemoryDumpArgs& args,
                    base::trace_event::ProcessMemoryDump* pmd) override;

 private:
  friend struct base::DefaultSingletonTraits<SqlMemoryDumpProvider>;

  SqlMemoryDumpProvider();
  ~SqlMemoryDumpProvider() override;

  DISALLOW_COPY_AND_ASSIGN(SqlMemoryDumpProvider);
};

}  // namespace sql

#endif  // SQL_SQL_MEMORY_DUMP_PROVIDER_H
