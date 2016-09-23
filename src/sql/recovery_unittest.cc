// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sql/recovery.h"

#include <stddef.h>

#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/path_service.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/histogram_tester.h"
#include "sql/connection.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/test/paths.h"
#include "sql/test/scoped_error_expecter.h"
#include "sql/test/sql_test_base.h"
#include "sql/test/test_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/sqlite/sqlite3.h"

namespace {

// Execute |sql|, and stringify the results with |column_sep| between
// columns and |row_sep| between rows.
// TODO(shess): Promote this to a central testing helper.
std::string ExecuteWithResults(sql::Connection* db,
                               const char* sql,
                               const char* column_sep,
                               const char* row_sep) {
  sql::Statement s(db->GetUniqueStatement(sql));
  std::string ret;
  while (s.Step()) {
    if (!ret.empty())
      ret += row_sep;
    for (int i = 0; i < s.ColumnCount(); ++i) {
      if (i > 0)
        ret += column_sep;
      if (s.ColumnType(i) == sql::COLUMN_TYPE_NULL) {
        ret += "<null>";
      } else if (s.ColumnType(i) == sql::COLUMN_TYPE_BLOB) {
        ret += "<x'";
        ret += base::HexEncode(s.ColumnBlob(i), s.ColumnByteLength(i));
        ret += "'>";
      } else {
        ret += s.ColumnString(i);
      }
    }
  }
  return ret;
}

// Dump consistent human-readable representation of the database
// schema.  For tables or indices, this will contain the sql command
// to create the table or index.  For certain automatic SQLite
// structures with no sql, the name is used.
std::string GetSchema(sql::Connection* db) {
  const char kSql[] =
      "SELECT COALESCE(sql, name) FROM sqlite_master ORDER BY 1";
  return ExecuteWithResults(db, kSql, "|", "\n");
}

using SQLRecoveryTest = sql::SQLTestBase;

// Baseline sql::Recovery test covering the different ways to dispose of the
// scoped pointer received from sql::Recovery::Begin().
TEST_F(SQLRecoveryTest, RecoverBasic) {
  const char kCreateSql[] = "CREATE TABLE x (t TEXT)";
  const char kInsertSql[] = "INSERT INTO x VALUES ('This is a test')";
  const char kAltInsertSql[] = "INSERT INTO x VALUES ('That was a test')";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kInsertSql));
  ASSERT_EQ("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  // If the Recovery handle goes out of scope without being
  // Recovered(), the database is razed.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery.get());
  }
  EXPECT_FALSE(db().is_open());
  ASSERT_TRUE(Reopen());
  EXPECT_TRUE(db().is_open());
  ASSERT_EQ("", GetSchema(&db()));

  // Recreate the database.
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kInsertSql));
  ASSERT_EQ("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  // Unrecoverable() also razes.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery.get());
    sql::Recovery::Unrecoverable(std::move(recovery));

    // TODO(shess): Test that calls to recover.db() start failing.
  }
  EXPECT_FALSE(db().is_open());
  ASSERT_TRUE(Reopen());
  EXPECT_TRUE(db().is_open());
  ASSERT_EQ("", GetSchema(&db()));

  // Attempting to recover a previously-recovered handle fails early.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery.get());
    recovery.reset();

    recovery = sql::Recovery::Begin(&db(), db_path());
    ASSERT_FALSE(recovery.get());
  }
  ASSERT_TRUE(Reopen());

  // Recreate the database.
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kInsertSql));
  ASSERT_EQ("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  // Unrecovered table to distinguish from recovered database.
  ASSERT_TRUE(db().Execute("CREATE TABLE y (c INTEGER)"));
  ASSERT_NE("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  // Recovered() replaces the original with the "recovered" version.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery.get());

    // Create the new version of the table.
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    // Insert different data to distinguish from original database.
    ASSERT_TRUE(recovery->db()->Execute(kAltInsertSql));

    // Successfully recovered.
    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }
  EXPECT_FALSE(db().is_open());
  ASSERT_TRUE(Reopen());
  EXPECT_TRUE(db().is_open());
  ASSERT_EQ("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  const char* kXSql = "SELECT * FROM x ORDER BY 1";
  ASSERT_EQ("That was a test",
            ExecuteWithResults(&db(), kXSql, "|", "\n"));

  // Reset the database contents.
  ASSERT_TRUE(db().Execute("DELETE FROM x"));
  ASSERT_TRUE(db().Execute(kInsertSql));

  // Rollback() discards recovery progress and leaves the database as it was.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery.get());

    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));
    ASSERT_TRUE(recovery->db()->Execute(kAltInsertSql));

    sql::Recovery::Rollback(std::move(recovery));
  }
  EXPECT_FALSE(db().is_open());
  ASSERT_TRUE(Reopen());
  EXPECT_TRUE(db().is_open());
  ASSERT_EQ("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  ASSERT_EQ("This is a test",
            ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

// Test operation of the virtual table used by sql::Recovery.
TEST_F(SQLRecoveryTest, VirtualTable) {
  const char kCreateSql[] = "CREATE TABLE x (t TEXT)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES ('This is a test')"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES ('That was a test')"));

  // Successfully recover the database.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());

    // Tables to recover original DB, now at [corrupt].
    const char kRecoveryCreateSql[] =
        "CREATE VIRTUAL TABLE temp.recover_x using recover("
        "  corrupt.x,"
        "  t TEXT STRICT"
        ")";
    ASSERT_TRUE(recovery->db()->Execute(kRecoveryCreateSql));

    // Re-create the original schema.
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    // Copy the data from the recovery tables to the new database.
    const char kRecoveryCopySql[] =
        "INSERT INTO x SELECT t FROM recover_x";
    ASSERT_TRUE(recovery->db()->Execute(kRecoveryCopySql));

    // Successfully recovered.
    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ("CREATE TABLE x (t TEXT)", GetSchema(&db()));

  const char* kXSql = "SELECT * FROM x ORDER BY 1";
  ASSERT_EQ("That was a test\nThis is a test",
            ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

void RecoveryCallback(sql::Connection* db, const base::FilePath& db_path,
                      const char* create_table, const char* create_index,
                      int* record_error, int error, sql::Statement* stmt) {
  *record_error = error;

  // Clear the error callback to prevent reentrancy.
  db->reset_error_callback();

  std::unique_ptr<sql::Recovery> recovery = sql::Recovery::Begin(db, db_path);
  ASSERT_TRUE(recovery.get());

  ASSERT_TRUE(recovery->db()->Execute(create_table));
  ASSERT_TRUE(recovery->db()->Execute(create_index));

  size_t rows = 0;
  ASSERT_TRUE(recovery->AutoRecoverTable("x", &rows));

  ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
}

// Build a database, corrupt it by making an index reference to
// deleted row, then recover when a query selects that row.
TEST_F(SQLRecoveryTest, RecoverCorruptIndex) {
  const char kCreateTable[] = "CREATE TABLE x (id INTEGER, v INTEGER)";
  const char kCreateIndex[] = "CREATE UNIQUE INDEX x_id ON x (id)";
  ASSERT_TRUE(db().Execute(kCreateTable));
  ASSERT_TRUE(db().Execute(kCreateIndex));

  // Insert a bit of data.
  {
    ASSERT_TRUE(db().BeginTransaction());

    const char kInsertSql[] = "INSERT INTO x (id, v) VALUES (?, ?)";
    sql::Statement s(db().GetUniqueStatement(kInsertSql));
    for (int i = 0; i < 10; ++i) {
      s.Reset(true);
      s.BindInt(0, i);
      s.BindInt(1, i);
      EXPECT_FALSE(s.Step());
      EXPECT_TRUE(s.Succeeded());
    }

    ASSERT_TRUE(db().CommitTransaction());
  }
  db().Close();

  // Delete a row from the table, while leaving the index entry which
  // references it.
  const char kDeleteSql[] = "DELETE FROM x WHERE id = 0";
  ASSERT_TRUE(sql::test::CorruptTableOrIndex(db_path(), "x_id", kDeleteSql));

  ASSERT_TRUE(Reopen());

  int error = SQLITE_OK;
  db().set_error_callback(base::Bind(&RecoveryCallback, &db(), db_path(),
                                     kCreateTable, kCreateIndex, &error));

  // This works before the callback is called.
  const char kTrivialSql[] = "SELECT COUNT(*) FROM sqlite_master";
  EXPECT_TRUE(db().IsSQLValid(kTrivialSql));

  // TODO(shess): Could this be delete?  Anything which fails should work.
  const char kSelectSql[] = "SELECT v FROM x WHERE id = 0";
  ASSERT_FALSE(db().Execute(kSelectSql));
  EXPECT_EQ(SQLITE_CORRUPT, error);

  // Database handle has been poisoned.
  EXPECT_FALSE(db().IsSQLValid(kTrivialSql));

  ASSERT_TRUE(Reopen());

  // The recovered table should reflect the deletion.
  const char kSelectAllSql[] = "SELECT v FROM x ORDER BY id";
  EXPECT_EQ("1,2,3,4,5,6,7,8,9",
            ExecuteWithResults(&db(), kSelectAllSql, "|", ","));

  // The failing statement should now succeed, with no results.
  EXPECT_EQ("", ExecuteWithResults(&db(), kSelectSql, "|", ","));
}

// Build a database, corrupt it by making a table contain a row not
// referenced by the index, then recover the database.
TEST_F(SQLRecoveryTest, RecoverCorruptTable) {
  const char kCreateTable[] = "CREATE TABLE x (id INTEGER, v INTEGER)";
  const char kCreateIndex[] = "CREATE UNIQUE INDEX x_id ON x (id)";
  ASSERT_TRUE(db().Execute(kCreateTable));
  ASSERT_TRUE(db().Execute(kCreateIndex));

  // Insert a bit of data.
  {
    ASSERT_TRUE(db().BeginTransaction());

    const char kInsertSql[] = "INSERT INTO x (id, v) VALUES (?, ?)";
    sql::Statement s(db().GetUniqueStatement(kInsertSql));
    for (int i = 0; i < 10; ++i) {
      s.Reset(true);
      s.BindInt(0, i);
      s.BindInt(1, i);
      EXPECT_FALSE(s.Step());
      EXPECT_TRUE(s.Succeeded());
    }

    ASSERT_TRUE(db().CommitTransaction());
  }
  db().Close();

  // Delete a row from the index while leaving a table entry.
  const char kDeleteSql[] = "DELETE FROM x WHERE id = 0";
  ASSERT_TRUE(sql::test::CorruptTableOrIndex(db_path(), "x", kDeleteSql));

  ASSERT_TRUE(Reopen());

  int error = SQLITE_OK;
  db().set_error_callback(base::Bind(&RecoveryCallback, &db(), db_path(),
                                     kCreateTable, kCreateIndex, &error));

  // Index shows one less than originally inserted.
  const char kCountSql[] = "SELECT COUNT (*) FROM x";
  EXPECT_EQ("9", ExecuteWithResults(&db(), kCountSql, "|", ","));

  // A full table scan shows all of the original data.  Using column [v] to
  // force use of the table rather than the index.
  const char kDistinctSql[] = "SELECT DISTINCT COUNT (v) FROM x";
  EXPECT_EQ("10", ExecuteWithResults(&db(), kDistinctSql, "|", ","));

  // Insert id 0 again.  Since it is not in the index, the insert
  // succeeds, but results in a duplicate value in the table.
  const char kInsertSql[] = "INSERT INTO x (id, v) VALUES (0, 100)";
  ASSERT_TRUE(db().Execute(kInsertSql));

  // Duplication is visible.
  EXPECT_EQ("10", ExecuteWithResults(&db(), kCountSql, "|", ","));
  EXPECT_EQ("11", ExecuteWithResults(&db(), kDistinctSql, "|", ","));

  // This works before the callback is called.
  const char kTrivialSql[] = "SELECT COUNT(*) FROM sqlite_master";
  EXPECT_TRUE(db().IsSQLValid(kTrivialSql));

  // TODO(shess): Figure out a statement which causes SQLite to notice the
  // corruption.  SELECT doesn't see errors because missing index values aren't
  // visible.  UPDATE or DELETE against v=0 don't see errors, even though the
  // index item is missing.  I suspect SQLite only deletes the key in these
  // cases, but doesn't verify that one or more keys were deleted.
  ASSERT_FALSE(db().Execute("INSERT INTO x (id, v) VALUES (0, 101)"));
  EXPECT_EQ(SQLITE_CONSTRAINT_UNIQUE, error);

  // Database handle has been poisoned.
  EXPECT_FALSE(db().IsSQLValid(kTrivialSql));

  ASSERT_TRUE(Reopen());

  // The recovered table has consistency between the index and the table.
  EXPECT_EQ("10", ExecuteWithResults(&db(), kCountSql, "|", ","));
  EXPECT_EQ("10", ExecuteWithResults(&db(), kDistinctSql, "|", ","));

  // Only one of the values is retained.
  const char kSelectSql[] = "SELECT v FROM x WHERE id = 0";
  const std::string results = ExecuteWithResults(&db(), kSelectSql, "|", ",");
  EXPECT_TRUE(results=="100" || results=="0") << "Actual results: " << results;
}

TEST_F(SQLRecoveryTest, Meta) {
  const int kVersion = 3;
  const int kCompatibleVersion = 2;

  {
    sql::MetaTable meta;
    EXPECT_TRUE(meta.Init(&db(), kVersion, kCompatibleVersion));
    EXPECT_EQ(kVersion, meta.GetVersionNumber());
  }

  // Test expected case where everything works.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    EXPECT_TRUE(recovery->SetupMeta());
    int version = 0;
    EXPECT_TRUE(recovery->GetMetaVersionNumber(&version));
    EXPECT_EQ(kVersion, version);

    sql::Recovery::Rollback(std::move(recovery));
  }
  ASSERT_TRUE(Reopen());  // Handle was poisoned.

  // Test version row missing.
  EXPECT_TRUE(db().Execute("DELETE FROM meta WHERE key = 'version'"));
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    EXPECT_TRUE(recovery->SetupMeta());
    int version = 0;
    EXPECT_FALSE(recovery->GetMetaVersionNumber(&version));
    EXPECT_EQ(0, version);

    sql::Recovery::Rollback(std::move(recovery));
  }
  ASSERT_TRUE(Reopen());  // Handle was poisoned.

  // Test meta table missing.
  EXPECT_TRUE(db().Execute("DROP TABLE meta"));
  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CORRUPT);  // From virtual table.
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    EXPECT_FALSE(recovery->SetupMeta());
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }
}

// Baseline AutoRecoverTable() test.
TEST_F(SQLRecoveryTest, AutoRecoverTable) {
  // BIGINT and VARCHAR to test type affinity.
  const char kCreateSql[] = "CREATE TABLE x (id BIGINT, t TEXT, v VARCHAR)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (11, 'This is', 'a test')"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (5, 'That was', 'a test')"));

  // Save aside a copy of the original schema and data.
  const std::string orig_schema(GetSchema(&db()));
  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  const std::string orig_data(ExecuteWithResults(&db(), kXSql, "|", "\n"));

  // Create a lame-duck table which will not be propagated by recovery to
  // detect that the recovery code actually ran.
  ASSERT_TRUE(db().Execute("CREATE TABLE y (c TEXT)"));
  ASSERT_NE(orig_schema, GetSchema(&db()));

  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    // Save a copy of the temp db's schema before recovering the table.
    const char kTempSchemaSql[] = "SELECT name, sql FROM sqlite_temp_master";
    const std::string temp_schema(
        ExecuteWithResults(recovery->db(), kTempSchemaSql, "|", "\n"));

    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(2u, rows);

    // Test that any additional temp tables were cleaned up.
    EXPECT_EQ(temp_schema,
              ExecuteWithResults(recovery->db(), kTempSchemaSql, "|", "\n"));

    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(orig_schema, GetSchema(&db()));
  ASSERT_EQ(orig_data, ExecuteWithResults(&db(), kXSql, "|", "\n"));

  // Recovery fails if the target table doesn't exist.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    // TODO(shess): Should this failure implicitly lead to Raze()?
    size_t rows = 0;
    EXPECT_FALSE(recovery->AutoRecoverTable("y", &rows));

    sql::Recovery::Unrecoverable(std::move(recovery));
  }
}

// Test that default values correctly replace nulls.  The recovery
// virtual table reads directly from the database, so DEFAULT is not
// interpretted at that level.
TEST_F(SQLRecoveryTest, AutoRecoverTableWithDefault) {
  ASSERT_TRUE(db().Execute("CREATE TABLE x (id INTEGER)"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (5)"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (15)"));

  // ALTER effectively leaves the new columns NULL in the first two
  // rows.  The row with 17 will get the default injected at insert
  // time, while the row with 42 will get the actual value provided.
  // Embedded "'" to make sure default-handling continues to be quoted
  // correctly.
  ASSERT_TRUE(db().Execute("ALTER TABLE x ADD COLUMN t TEXT DEFAULT 'a''a'"));
  ASSERT_TRUE(db().Execute("ALTER TABLE x ADD COLUMN b BLOB DEFAULT x'AA55'"));
  ASSERT_TRUE(db().Execute("ALTER TABLE x ADD COLUMN i INT DEFAULT 93"));
  ASSERT_TRUE(db().Execute("INSERT INTO x (id) VALUES (17)"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (42, 'b', x'1234', 12)"));

  // Save aside a copy of the original schema and data.
  const std::string orig_schema(GetSchema(&db()));
  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  const std::string orig_data(ExecuteWithResults(&db(), kXSql, "|", "\n"));

  // Create a lame-duck table which will not be propagated by recovery to
  // detect that the recovery code actually ran.
  ASSERT_TRUE(db().Execute("CREATE TABLE y (c TEXT)"));
  ASSERT_NE(orig_schema, GetSchema(&db()));

  // Mechanically adjust the stored schema and data to allow detecting
  // where the default value is coming from.  The target table is just
  // like the original with the default for [t] changed, to signal
  // defaults coming from the recovery system.  The two %5 rows should
  // get the target-table default for [t], while the others should get
  // the source-table default.
  std::string final_schema(orig_schema);
  std::string final_data(orig_data);
  size_t pos;
  while ((pos = final_schema.find("'a''a'")) != std::string::npos) {
    final_schema.replace(pos, 6, "'c''c'");
  }
  while ((pos = final_data.find("5|a'a")) != std::string::npos) {
    final_data.replace(pos, 5, "5|c'c");
  }

  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    // Different default to detect which table provides the default.
    ASSERT_TRUE(recovery->db()->Execute(final_schema.c_str()));

    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(4u, rows);

    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(final_schema, GetSchema(&db()));
  ASSERT_EQ(final_data, ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

// Test that rows with NULL in a NOT NULL column are filtered
// correctly.  In the wild, this would probably happen due to
// corruption, but here it is simulated by recovering a table which
// allowed nulls into a table which does not.
TEST_F(SQLRecoveryTest, AutoRecoverTableNullFilter) {
  const char kOrigSchema[] = "CREATE TABLE x (id INTEGER, t TEXT)";
  const char kFinalSchema[] = "CREATE TABLE x (id INTEGER, t TEXT NOT NULL)";

  ASSERT_TRUE(db().Execute(kOrigSchema));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (5, null)"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (15, 'this is a test')"));

  // Create a lame-duck table which will not be propagated by recovery to
  // detect that the recovery code actually ran.
  ASSERT_EQ(kOrigSchema, GetSchema(&db()));
  ASSERT_TRUE(db().Execute("CREATE TABLE y (c TEXT)"));
  ASSERT_NE(kOrigSchema, GetSchema(&db()));

  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery->db()->Execute(kFinalSchema));

    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(1u, rows);

    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // The schema should be the same, but only one row of data should
  // have been recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(kFinalSchema, GetSchema(&db()));
  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  ASSERT_EQ("15|this is a test", ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

// Test AutoRecoverTable with a ROWID alias.
TEST_F(SQLRecoveryTest, AutoRecoverTableWithRowid) {
  // The rowid alias is almost always the first column, intentionally
  // put it later.
  const char kCreateSql[] =
      "CREATE TABLE x (t TEXT, id INTEGER PRIMARY KEY NOT NULL)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES ('This is a test', null)"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES ('That was a test', null)"));

  // Save aside a copy of the original schema and data.
  const std::string orig_schema(GetSchema(&db()));
  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  const std::string orig_data(ExecuteWithResults(&db(), kXSql, "|", "\n"));

  // Create a lame-duck table which will not be propagated by recovery to
  // detect that the recovery code actually ran.
  ASSERT_TRUE(db().Execute("CREATE TABLE y (c TEXT)"));
  ASSERT_NE(orig_schema, GetSchema(&db()));

  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(2u, rows);

    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(orig_schema, GetSchema(&db()));
  ASSERT_EQ(orig_data, ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

// Test that a compound primary key doesn't fire the ROWID code.
TEST_F(SQLRecoveryTest, AutoRecoverTableWithCompoundKey) {
  const char kCreateSql[] =
      "CREATE TABLE x ("
      "id INTEGER NOT NULL,"
      "id2 TEXT NOT NULL,"
      "t TEXT,"
      "PRIMARY KEY (id, id2)"
      ")";
  ASSERT_TRUE(db().Execute(kCreateSql));

  // NOTE(shess): Do not accidentally use [id] 1, 2, 3, as those will
  // be the ROWID values.
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (1, 'a', 'This is a test')"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (1, 'b', 'That was a test')"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (2, 'a', 'Another test')"));

  // Save aside a copy of the original schema and data.
  const std::string orig_schema(GetSchema(&db()));
  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  const std::string orig_data(ExecuteWithResults(&db(), kXSql, "|", "\n"));

  // Create a lame-duck table which will not be propagated by recovery to
  // detect that the recovery code actually ran.
  ASSERT_TRUE(db().Execute("CREATE TABLE y (c TEXT)"));
  ASSERT_NE(orig_schema, GetSchema(&db()));

  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(3u, rows);

    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(orig_schema, GetSchema(&db()));
  ASSERT_EQ(orig_data, ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

// Test recovering from a table with fewer columns than the target.
TEST_F(SQLRecoveryTest, AutoRecoverTableMissingColumns) {
  const char kCreateSql[] = "CREATE TABLE x (id INTEGER PRIMARY KEY, t0 TEXT)";
  const char kAlterSql[] = "ALTER TABLE x ADD COLUMN t1 TEXT DEFAULT 't'";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (1, 'This is')"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES (2, 'That was')"));

  // Generate the expected info by faking a table to match what recovery will
  // create.
  const std::string orig_schema(GetSchema(&db()));
  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  std::string expected_schema;
  std::string expected_data;
  {
    ASSERT_TRUE(db().BeginTransaction());
    ASSERT_TRUE(db().Execute(kAlterSql));

    expected_schema = GetSchema(&db());
    expected_data = ExecuteWithResults(&db(), kXSql, "|", "\n");

    db().RollbackTransaction();
  }

  // Following tests are pointless if the rollback didn't work.
  ASSERT_EQ(orig_schema, GetSchema(&db()));

  // Recover the previous version of the table into the altered version.
  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));
    ASSERT_TRUE(recovery->db()->Execute(kAlterSql));
    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(2u, rows);
    ASSERT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(expected_schema, GetSchema(&db()));
  ASSERT_EQ(expected_data, ExecuteWithResults(&db(), kXSql, "|", "\n"));
}

// Recover a golden file where an interior page has been manually modified so
// that the number of cells is greater than will fit on a single page.  This
// case happened in <http://crbug.com/387868>.
TEST_F(SQLRecoveryTest, Bug387868) {
  base::FilePath golden_path;
  ASSERT_TRUE(PathService::Get(sql::test::DIR_TEST_DATA, &golden_path));
  golden_path = golden_path.AppendASCII("recovery_387868");
  db().Close();
  ASSERT_TRUE(base::CopyFile(golden_path, db_path()));
  ASSERT_TRUE(Reopen());

  {
    std::unique_ptr<sql::Recovery> recovery =
        sql::Recovery::Begin(&db(), db_path());
    ASSERT_TRUE(recovery.get());

    // Create the new version of the table.
    const char kCreateSql[] =
        "CREATE TABLE x (id INTEGER PRIMARY KEY, t0 TEXT)";
    ASSERT_TRUE(recovery->db()->Execute(kCreateSql));

    size_t rows = 0;
    EXPECT_TRUE(recovery->AutoRecoverTable("x", &rows));
    EXPECT_EQ(43u, rows);

    // Successfully recovered.
    EXPECT_TRUE(sql::Recovery::Recovered(std::move(recovery)));
  }
}

// Memory-mapped I/O interacts poorly with I/O errors.  Make sure the recovery
// database doesn't accidentally enable it.
TEST_F(SQLRecoveryTest, NoMmap) {
  std::unique_ptr<sql::Recovery> recovery =
      sql::Recovery::Begin(&db(), db_path());
  ASSERT_TRUE(recovery.get());

  // In the current implementation, the PRAGMA successfully runs with no result
  // rows.  Running with a single result of |0| is also acceptable.
  sql::Statement s(recovery->db()->GetUniqueStatement("PRAGMA mmap_size"));
  EXPECT_TRUE(!s.Step() || !s.ColumnInt64(0));
}

TEST_F(SQLRecoveryTest, RecoverDatabase) {
  // As a side effect, AUTOINCREMENT creates the sqlite_sequence table for
  // RecoverDatabase() to handle.
  ASSERT_TRUE(db().Execute(
      "CREATE TABLE x (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT)"));
  EXPECT_TRUE(db().Execute("INSERT INTO x (v) VALUES ('turtle')"));
  EXPECT_TRUE(db().Execute("INSERT INTO x (v) VALUES ('truck')"));
  EXPECT_TRUE(db().Execute("INSERT INTO x (v) VALUES ('trailer')"));

  // This table needs index and a unique index to work.
  ASSERT_TRUE(db().Execute("CREATE TABLE y (name TEXT, v TEXT)"));
  ASSERT_TRUE(db().Execute("CREATE UNIQUE INDEX y_name ON y(name)"));
  ASSERT_TRUE(db().Execute("CREATE INDEX y_v ON y(v)"));
  EXPECT_TRUE(db().Execute("INSERT INTO y VALUES ('jim', 'telephone')"));
  EXPECT_TRUE(db().Execute("INSERT INTO y VALUES ('bob', 'truck')"));
  EXPECT_TRUE(db().Execute("INSERT INTO y VALUES ('dean', 'trailer')"));

  // View which is the intersection of [x.v] and [y.v].
  ASSERT_TRUE(db().Execute(
      "CREATE VIEW v AS SELECT x.v FROM x, y WHERE x.v = y.v"));

  // When an element is deleted from [x], trigger a delete on [y].  Between the
  // BEGIN and END, [old] stands for the deleted rows from [x].
  ASSERT_TRUE(db().Execute("CREATE TRIGGER t AFTER DELETE ON x "
                           "BEGIN DELETE FROM y WHERE y.v = old.v; END"));

  // Save aside a copy of the original schema, verifying that it has the created
  // items plus the sqlite_sequence table.
  const std::string orig_schema(GetSchema(&db()));
  ASSERT_EQ(6, std::count(orig_schema.begin(), orig_schema.end(), '\n'));

  const char kXSql[] = "SELECT * FROM x ORDER BY 1";
  const char kYSql[] = "SELECT * FROM y ORDER BY 1";
  const char kVSql[] = "SELECT * FROM v ORDER BY 1";
  EXPECT_EQ("1|turtle\n2|truck\n3|trailer",
            ExecuteWithResults(&db(), kXSql, "|", "\n"));
  EXPECT_EQ("bob|truck\ndean|trailer\njim|telephone",
            ExecuteWithResults(&db(), kYSql, "|", "\n"));
  EXPECT_EQ("trailer\ntruck", ExecuteWithResults(&db(), kVSql, "|", "\n"));

  // Database handle is valid before recovery, poisoned after.
  const char kTrivialSql[] = "SELECT COUNT(*) FROM sqlite_master";
  EXPECT_TRUE(db().IsSQLValid(kTrivialSql));
  sql::Recovery::RecoverDatabase(&db(), db_path());
  EXPECT_FALSE(db().IsSQLValid(kTrivialSql));

  // Since the database was not corrupt, the entire schema and all
  // data should be recovered.
  ASSERT_TRUE(Reopen());
  ASSERT_EQ(orig_schema, GetSchema(&db()));
  EXPECT_EQ("1|turtle\n2|truck\n3|trailer",
            ExecuteWithResults(&db(), kXSql, "|", "\n"));
  EXPECT_EQ("bob|truck\ndean|trailer\njim|telephone",
            ExecuteWithResults(&db(), kYSql, "|", "\n"));
  EXPECT_EQ("trailer\ntruck", ExecuteWithResults(&db(), kVSql, "|", "\n"));

  // Test that the trigger works.
  ASSERT_TRUE(db().Execute("DELETE FROM x WHERE v = 'truck'"));
  EXPECT_EQ("1|turtle\n3|trailer",
            ExecuteWithResults(&db(), kXSql, "|", "\n"));
  EXPECT_EQ("dean|trailer\njim|telephone",
            ExecuteWithResults(&db(), kYSql, "|", "\n"));
  EXPECT_EQ("trailer", ExecuteWithResults(&db(), kVSql, "|", "\n"));
}

// Test histograms recorded when the invalid database cannot be attached.
TEST_F(SQLRecoveryTest, AttachFailure) {
  // Create a valid database, then write junk over the header.  This should lead
  // to SQLITE_NOTADB, which will cause ATTACH to fail.
  ASSERT_TRUE(db().Execute("CREATE TABLE x (t TEXT)"));
  ASSERT_TRUE(db().Execute("INSERT INTO x VALUES ('This is a test')"));
  db().Close();
  WriteJunkToDatabase(SQLTestBase::TYPE_OVERWRITE);

  const char kEventHistogramName[] = "Sqlite.RecoveryEvents";
  const int kEventEnum = 5;  // RECOVERY_FAILED_ATTACH
  const char kErrorHistogramName[] = "Sqlite.RecoveryAttachError";
  base::HistogramTester tester;

  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_NOTADB);

    // Reopen() here because it will see SQLITE_NOTADB.
    ASSERT_TRUE(Reopen());

    // Begin() should fail.
    std::unique_ptr<sql::Recovery>
        recovery = sql::Recovery::Begin(&db(), db_path());
    ASSERT_FALSE(recovery.get());

    ASSERT_TRUE(expecter.SawExpectedErrors());
  }

  // Verify that the failure was in the right place with the expected code.
  tester.ExpectBucketCount(kEventHistogramName, kEventEnum, 1);
  tester.ExpectBucketCount(kErrorHistogramName, SQLITE_NOTADB, 1);
}

}  // namespace
