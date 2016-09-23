// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sql/test/test_helpers.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "sql/connection.h"
#include "sql/statement.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

size_t CountSQLItemsOfType(sql::Connection* db, const char* type) {
  const char kTypeSQL[] = "SELECT COUNT(*) FROM sqlite_master WHERE type = ?";
  sql::Statement s(db->GetUniqueStatement(kTypeSQL));
  s.BindCString(0, type);
  EXPECT_TRUE(s.Step());
  return s.ColumnInt(0);
}

// Get page size for the database.
bool GetPageSize(sql::Connection* db, int* page_size) {
  sql::Statement s(db->GetUniqueStatement("PRAGMA page_size"));
  if (!s.Step())
    return false;
  *page_size = s.ColumnInt(0);
  return true;
}

// Get |name|'s root page number in the database.
bool GetRootPage(sql::Connection* db, const char* name, int* page_number) {
  const char kPageSql[] = "SELECT rootpage FROM sqlite_master WHERE name = ?";
  sql::Statement s(db->GetUniqueStatement(kPageSql));
  s.BindString(0, name);
  if (!s.Step())
    return false;
  *page_number = s.ColumnInt(0);
  return true;
}

// Helper for reading a number from the SQLite header.
// See base/big_endian.h.
unsigned ReadBigEndian(unsigned char* buf, size_t bytes) {
  unsigned r = buf[0];
  for (size_t i = 1; i < bytes; i++) {
    r <<= 8;
    r |= buf[i];
  }
  return r;
}

// Helper for writing a number to the SQLite header.
void WriteBigEndian(unsigned val, unsigned char* buf, size_t bytes) {
  for (size_t i = 0; i < bytes; i++) {
    buf[bytes - i - 1] = (val & 0xFF);
    val >>= 8;
  }
}

}  // namespace

namespace sql {
namespace test {

bool CorruptSizeInHeader(const base::FilePath& db_path) {
  // See http://www.sqlite.org/fileformat.html#database_header
  const size_t kHeaderSize = 100;

  unsigned char header[kHeaderSize];

  base::ScopedFILE file(base::OpenFile(db_path, "rb+"));
  if (!file.get())
    return false;

  if (0 != fseek(file.get(), 0, SEEK_SET))
    return false;
  if (1u != fread(header, sizeof(header), 1, file.get()))
    return false;

  int64_t db_size = 0;
  if (!base::GetFileSize(db_path, &db_size))
    return false;

  CorruptSizeInHeaderMemory(header, db_size);

  if (0 != fseek(file.get(), 0, SEEK_SET))
    return false;
  if (1u != fwrite(header, sizeof(header), 1, file.get()))
    return false;

  return true;
}

void CorruptSizeInHeaderMemory(unsigned char* header, int64_t db_size) {
  const size_t kPageSizeOffset = 16;
  const size_t kFileChangeCountOffset = 24;
  const size_t kPageCountOffset = 28;
  const size_t kVersionValidForOffset = 92;  // duplicate kFileChangeCountOffset

  const unsigned page_size = ReadBigEndian(header + kPageSizeOffset, 2);

  // One larger than the expected size.
  const unsigned page_count =
      static_cast<unsigned>((db_size + page_size) / page_size);
  WriteBigEndian(page_count, header + kPageCountOffset, 4);

  // Update change count so outstanding readers know the info changed.
  // Both spots must match for the page count to be considered valid.
  unsigned change_count = ReadBigEndian(header + kFileChangeCountOffset, 4);
  WriteBigEndian(change_count + 1, header + kFileChangeCountOffset, 4);
  WriteBigEndian(change_count + 1, header + kVersionValidForOffset, 4);
}

bool CorruptTableOrIndex(const base::FilePath& db_path,
                         const char* tree_name,
                         const char* update_sql) {
  sql::Connection db;
  if (!db.Open(db_path))
    return false;

  int page_size = 0;
  if (!GetPageSize(&db, &page_size))
    return false;

  int page_number = 0;
  if (!GetRootPage(&db, tree_name, &page_number))
    return false;

  // SQLite uses 1-based page numbering.
  const long int page_ofs = (page_number - 1) * page_size;
  std::unique_ptr<char[]> page_buf(new char[page_size]);

  // Get the page into page_buf.
  base::ScopedFILE file(base::OpenFile(db_path, "rb+"));
  if (!file.get())
    return false;
  if (0 != fseek(file.get(), page_ofs, SEEK_SET))
    return false;
  if (1u != fread(page_buf.get(), page_size, 1, file.get()))
    return false;

  // Require the page to be a leaf node.  A multilevel tree would be
  // very hard to restore correctly.
  if (page_buf[0] != 0xD && page_buf[0] != 0xA)
    return false;

  // The update has to work, and make changes.
  if (!db.Execute(update_sql))
    return false;
  if (db.GetLastChangeCount() == 0)
    return false;

  // Ensure that the database is fully flushed.
  db.Close();

  // Check that the stored page actually changed.  This catches usage
  // errors where |update_sql| is not related to |tree_name|.
  std::unique_ptr<char[]> check_page_buf(new char[page_size]);
  // The on-disk data should have changed.
  if (0 != fflush(file.get()))
    return false;
  if (0 != fseek(file.get(), page_ofs, SEEK_SET))
    return false;
  if (1u != fread(check_page_buf.get(), page_size, 1, file.get()))
    return false;
  if (!memcmp(check_page_buf.get(), page_buf.get(), page_size))
    return false;

  // Put the original page back.
  if (0 != fseek(file.get(), page_ofs, SEEK_SET))
    return false;
  if (1u != fwrite(page_buf.get(), page_size, 1, file.get()))
    return false;

  return true;
}

size_t CountSQLTables(sql::Connection* db) {
  return CountSQLItemsOfType(db, "table");
}

size_t CountSQLIndices(sql::Connection* db) {
  return CountSQLItemsOfType(db, "index");
}

size_t CountTableColumns(sql::Connection* db, const char* table) {
  // TODO(shess): sql::Connection::QuoteForSQL() would make sense.
  std::string quoted_table;
  {
    const char kQuoteSQL[] = "SELECT quote(?)";
    sql::Statement s(db->GetUniqueStatement(kQuoteSQL));
    s.BindCString(0, table);
    EXPECT_TRUE(s.Step());
    quoted_table = s.ColumnString(0);
  }

  std::string sql = "PRAGMA table_info(" + quoted_table + ")";
  sql::Statement s(db->GetUniqueStatement(sql.c_str()));
  size_t rows = 0;
  while (s.Step()) {
    ++rows;
  }
  EXPECT_TRUE(s.Succeeded());
  return rows;
}

bool CountTableRows(sql::Connection* db, const char* table, size_t* count) {
  // TODO(shess): Table should probably be quoted with [] or "".  See
  // http://www.sqlite.org/lang_keywords.html .  Meanwhile, odd names
  // will throw an error.
  std::string sql = "SELECT COUNT(*) FROM ";
  sql += table;
  sql::Statement s(db->GetUniqueStatement(sql.c_str()));
  if (!s.Step())
    return false;

  *count = static_cast<size_t>(s.ColumnInt64(0));
  return true;
}

bool CreateDatabaseFromSQL(const base::FilePath& db_path,
                           const base::FilePath& sql_path) {
  if (base::PathExists(db_path) || !base::PathExists(sql_path))
    return false;

  std::string sql;
  if (!base::ReadFileToString(sql_path, &sql))
    return false;

  sql::Connection db;
  if (!db.Open(db_path))
    return false;

  // TODO(shess): Android defaults to auto_vacuum mode.
  // Unfortunately, this makes certain kinds of tests which manipulate
  // the raw database hard/impossible to write.
  // http://crbug.com/307303 is for exploring this test issue.
  ignore_result(db.Execute("PRAGMA auto_vacuum = 0"));

  return db.Execute(sql.c_str());
}

std::string IntegrityCheck(sql::Connection* db) {
  sql::Statement statement(db->GetUniqueStatement("PRAGMA integrity_check"));

  // SQLite should always return a row of data.
  EXPECT_TRUE(statement.Step());

  return statement.ColumnString(0);
}

}  // namespace test
}  // namespace sql
