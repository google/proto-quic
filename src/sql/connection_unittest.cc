// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "base/bind.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/files/scoped_temp_dir.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/statistics_recorder.h"
#include "base/test/histogram_tester.h"
#include "base/trace_event/process_memory_dump.h"
#include "sql/connection.h"
#include "sql/connection_memory_dump_provider.h"
#include "sql/correct_sql_test_base.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "sql/test/error_callback_support.h"
#include "sql/test/scoped_error_expecter.h"
#include "sql/test/test_helpers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/sqlite/sqlite3.h"

#if defined(OS_IOS) && defined(USE_SYSTEM_SQLITE)
#include "base/ios/ios_util.h"
#endif

namespace sql {
namespace test {

// Replaces the database time source with an object that steps forward 1ms on
// each check, and which can be jumped forward an arbitrary amount of time
// programmatically.
class ScopedMockTimeSource {
 public:
  ScopedMockTimeSource(Connection& db)
      : db_(db),
        delta_(base::TimeDelta::FromMilliseconds(1)) {
    // Save the current source and replace it.
    save_.swap(db_.clock_);
    db_.clock_.reset(new MockTimeSource(*this));
  }
  ~ScopedMockTimeSource() {
    // Put original source back.
    db_.clock_.swap(save_);
  }

  void adjust(const base::TimeDelta& delta) {
    current_time_ += delta;
  }

 private:
  class MockTimeSource : public TimeSource {
   public:
    MockTimeSource(ScopedMockTimeSource& owner)
        : owner_(owner) {
    }
    ~MockTimeSource() override {}

    base::TimeTicks Now() override {
      base::TimeTicks ret(owner_.current_time_);
      owner_.current_time_ += owner_.delta_;
      return ret;
    }

   private:
    ScopedMockTimeSource& owner_;
    DISALLOW_COPY_AND_ASSIGN(MockTimeSource);
  };

  Connection& db_;

  // Saves original source from |db_|.
  std::unique_ptr<TimeSource> save_;

  // Current time returned by mock.
  base::TimeTicks current_time_;

  // How far to jump on each Now() call.
  base::TimeDelta delta_;

  DISALLOW_COPY_AND_ASSIGN(ScopedMockTimeSource);
};

// Allow a test to add a SQLite function in a scoped context.
class ScopedScalarFunction {
 public:
  ScopedScalarFunction(
      sql::Connection& db,
      const char* function_name,
      int args,
      base::Callback<void(sqlite3_context*,int,sqlite3_value**)> cb)
      : db_(db.db_), function_name_(function_name), cb_(cb) {
    sqlite3_create_function_v2(db_, function_name, args, SQLITE_UTF8,
                               this, &Run, NULL, NULL, NULL);
  }
  ~ScopedScalarFunction() {
    sqlite3_create_function_v2(db_, function_name_, 0, SQLITE_UTF8,
                               NULL, NULL, NULL, NULL, NULL);
  }

 private:
  static void Run(sqlite3_context* context, int argc, sqlite3_value** argv) {
    ScopedScalarFunction* t = static_cast<ScopedScalarFunction*>(
        sqlite3_user_data(context));
    t->cb_.Run(context, argc, argv);
  }

  sqlite3* db_;
  const char* function_name_;
  base::Callback<void(sqlite3_context*,int,sqlite3_value**)> cb_;

  DISALLOW_COPY_AND_ASSIGN(ScopedScalarFunction);
};

// Allow a test to add a SQLite commit hook in a scoped context.
class ScopedCommitHook {
 public:
  ScopedCommitHook(sql::Connection& db,
                   base::Callback<int(void)> cb)
      : db_(db.db_),
        cb_(cb) {
    sqlite3_commit_hook(db_, &Run, this);
  }
  ~ScopedCommitHook() {
    sqlite3_commit_hook(db_, NULL, NULL);
  }

 private:
  static int Run(void* p) {
    ScopedCommitHook* t = static_cast<ScopedCommitHook*>(p);
    return t->cb_.Run();
  }

  sqlite3* db_;
  base::Callback<int(void)> cb_;

  DISALLOW_COPY_AND_ASSIGN(ScopedCommitHook);
};

}  // namespace test

namespace {

// Helper to return the count of items in sqlite_master.  Return -1 in
// case of error.
int SqliteMasterCount(sql::Connection* db) {
  const char* kMasterCount = "SELECT COUNT(*) FROM sqlite_master";
  sql::Statement s(db->GetUniqueStatement(kMasterCount));
  return s.Step() ? s.ColumnInt(0) : -1;
}

// Track the number of valid references which share the same pointer.
// This is used to allow testing an implicitly use-after-free case by
// explicitly having the ref count live longer than the object.
class RefCounter {
 public:
  RefCounter(size_t* counter)
      : counter_(counter) {
    (*counter_)++;
  }
  RefCounter(const RefCounter& other)
      : counter_(other.counter_) {
    (*counter_)++;
  }
  ~RefCounter() {
    (*counter_)--;
  }

 private:
  size_t* counter_;

  DISALLOW_ASSIGN(RefCounter);
};

// Empty callback for implementation of ErrorCallbackSetHelper().
void IgnoreErrorCallback(int error, sql::Statement* stmt) {
}

void ErrorCallbackSetHelper(sql::Connection* db,
                            size_t* counter,
                            const RefCounter& r,
                            int error, sql::Statement* stmt) {
  // The ref count should not go to zero when changing the callback.
  EXPECT_GT(*counter, 0u);
  db->set_error_callback(base::Bind(&IgnoreErrorCallback));
  EXPECT_GT(*counter, 0u);
}

void ErrorCallbackResetHelper(sql::Connection* db,
                              size_t* counter,
                              const RefCounter& r,
                              int error, sql::Statement* stmt) {
  // The ref count should not go to zero when clearing the callback.
  EXPECT_GT(*counter, 0u);
  db->reset_error_callback();
  EXPECT_GT(*counter, 0u);
}

#if defined(OS_POSIX)
// Set a umask and restore the old mask on destruction.  Cribbed from
// shared_memory_unittest.cc.  Used by POSIX-only UserPermission test.
class ScopedUmaskSetter {
 public:
  explicit ScopedUmaskSetter(mode_t target_mask) {
    old_umask_ = umask(target_mask);
  }
  ~ScopedUmaskSetter() { umask(old_umask_); }
 private:
  mode_t old_umask_;
  DISALLOW_IMPLICIT_CONSTRUCTORS(ScopedUmaskSetter);
};
#endif

// SQLite function to adjust mock time by |argv[0]| milliseconds.
void sqlite_adjust_millis(sql::test::ScopedMockTimeSource* time_mock,
                          sqlite3_context* context,
                          int argc, sqlite3_value** argv) {
  int64_t milliseconds = argc > 0 ? sqlite3_value_int64(argv[0]) : 1000;
  time_mock->adjust(base::TimeDelta::FromMilliseconds(milliseconds));
  sqlite3_result_int64(context, milliseconds);
}

// Adjust mock time by |milliseconds| on commit.
int adjust_commit_hook(sql::test::ScopedMockTimeSource* time_mock,
                       int64_t milliseconds) {
  time_mock->adjust(base::TimeDelta::FromMilliseconds(milliseconds));
  return SQLITE_OK;
}

const char kCommitTime[] = "Sqlite.CommitTime.Test";
const char kAutoCommitTime[] = "Sqlite.AutoCommitTime.Test";
const char kUpdateTime[] = "Sqlite.UpdateTime.Test";
const char kQueryTime[] = "Sqlite.QueryTime.Test";

}  // namespace

class SQLConnectionTest : public sql::SQLTestBase {
 public:
  void SetUp() override {
    // Any macro histograms which fire before the recorder is initialized cannot
    // be tested.  So this needs to be ahead of Open().
    base::StatisticsRecorder::Initialize();

    SQLTestBase::SetUp();
  }

  // Handle errors by blowing away the database.
  void RazeErrorCallback(int expected_error, int error, sql::Statement* stmt) {
    // Nothing here needs extended errors at this time.
    EXPECT_EQ(expected_error, expected_error&0xff);
    EXPECT_EQ(expected_error, error&0xff);
    db().RazeAndClose();
  }
};

TEST_F(SQLConnectionTest, Execute) {
  // Valid statement should return true.
  ASSERT_TRUE(db().Execute("CREATE TABLE foo (a, b)"));
  EXPECT_EQ(SQLITE_OK, db().GetErrorCode());

  // Invalid statement should fail.
  ASSERT_EQ(SQLITE_ERROR,
            db().ExecuteAndReturnErrorCode("CREATE TAB foo (a, b"));
  EXPECT_EQ(SQLITE_ERROR, db().GetErrorCode());
}

TEST_F(SQLConnectionTest, ExecuteWithErrorCode) {
  ASSERT_EQ(SQLITE_OK,
            db().ExecuteAndReturnErrorCode("CREATE TABLE foo (a, b)"));
  ASSERT_EQ(SQLITE_ERROR,
            db().ExecuteAndReturnErrorCode("CREATE TABLE TABLE"));
  ASSERT_EQ(SQLITE_ERROR,
            db().ExecuteAndReturnErrorCode(
                "INSERT INTO foo(a, b) VALUES (1, 2, 3, 4)"));
}

TEST_F(SQLConnectionTest, CachedStatement) {
  sql::StatementID id1("foo", 12);

  ASSERT_TRUE(db().Execute("CREATE TABLE foo (a, b)"));
  ASSERT_TRUE(db().Execute("INSERT INTO foo(a, b) VALUES (12, 13)"));

  // Create a new cached statement.
  {
    sql::Statement s(db().GetCachedStatement(id1, "SELECT a FROM foo"));
    ASSERT_TRUE(s.is_valid());

    ASSERT_TRUE(s.Step());
    EXPECT_EQ(12, s.ColumnInt(0));
  }

  // The statement should be cached still.
  EXPECT_TRUE(db().HasCachedStatement(id1));

  {
    // Get the same statement using different SQL. This should ignore our
    // SQL and use the cached one (so it will be valid).
    sql::Statement s(db().GetCachedStatement(id1, "something invalid("));
    ASSERT_TRUE(s.is_valid());

    ASSERT_TRUE(s.Step());
    EXPECT_EQ(12, s.ColumnInt(0));
  }

  // Make sure other statements aren't marked as cached.
  EXPECT_FALSE(db().HasCachedStatement(SQL_FROM_HERE));
}

TEST_F(SQLConnectionTest, IsSQLValidTest) {
  ASSERT_TRUE(db().Execute("CREATE TABLE foo (a, b)"));
  ASSERT_TRUE(db().IsSQLValid("SELECT a FROM foo"));
  ASSERT_FALSE(db().IsSQLValid("SELECT no_exist FROM foo"));
}

TEST_F(SQLConnectionTest, DoesStuffExist) {
  // Test DoesTableExist.
  EXPECT_FALSE(db().DoesTableExist("foo"));
  ASSERT_TRUE(db().Execute("CREATE TABLE foo (a, b)"));
  ASSERT_TRUE(db().Execute("CREATE INDEX foo_a ON foo (a)"));
  EXPECT_TRUE(db().DoesTableExist("foo"));
  EXPECT_TRUE(db().DoesIndexExist("foo_a"));

  // Test DoesColumnExist.
  EXPECT_FALSE(db().DoesColumnExist("foo", "bar"));
  EXPECT_TRUE(db().DoesColumnExist("foo", "a"));

  // Testing for a column on a nonexistent table.
  EXPECT_FALSE(db().DoesColumnExist("bar", "b"));

  // Names are not case sensitive.
  EXPECT_TRUE(db().DoesTableExist("FOO"));
  EXPECT_TRUE(db().DoesColumnExist("FOO", "A"));
}

TEST_F(SQLConnectionTest, GetLastInsertRowId) {
  ASSERT_TRUE(db().Execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, value)"));

  ASSERT_TRUE(db().Execute("INSERT INTO foo (value) VALUES (12)"));

  // Last insert row ID should be valid.
  int64_t row = db().GetLastInsertRowId();
  EXPECT_LT(0, row);

  // It should be the primary key of the row we just inserted.
  sql::Statement s(db().GetUniqueStatement("SELECT value FROM foo WHERE id=?"));
  s.BindInt64(0, row);
  ASSERT_TRUE(s.Step());
  EXPECT_EQ(12, s.ColumnInt(0));
}

TEST_F(SQLConnectionTest, Rollback) {
  ASSERT_TRUE(db().BeginTransaction());
  ASSERT_TRUE(db().BeginTransaction());
  EXPECT_EQ(2, db().transaction_nesting());
  db().RollbackTransaction();
  EXPECT_FALSE(db().CommitTransaction());
  EXPECT_TRUE(db().BeginTransaction());
}

// Test the scoped error expecter by attempting to insert a duplicate
// value into an index.
TEST_F(SQLConnectionTest, ScopedErrorExpecter) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER UNIQUE)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO foo (id) VALUES (12)"));

  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CONSTRAINT);
    ASSERT_FALSE(db().Execute("INSERT INTO foo (id) VALUES (12)"));
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }
}

// Test that clients of GetUntrackedStatement() can test corruption-handling
// with ScopedErrorExpecter.
TEST_F(SQLConnectionTest, ScopedIgnoreUntracked) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER UNIQUE)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_FALSE(db().DoesTableExist("bar"));
  ASSERT_TRUE(db().DoesTableExist("foo"));
  ASSERT_TRUE(db().DoesColumnExist("foo", "id"));
  db().Close();

  // Corrupt the database so that nothing works, including PRAGMAs.
  ASSERT_TRUE(CorruptSizeInHeaderOfDB());

  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CORRUPT);
    ASSERT_TRUE(db().Open(db_path()));
    ASSERT_FALSE(db().DoesTableExist("bar"));
    ASSERT_FALSE(db().DoesTableExist("foo"));
    ASSERT_FALSE(db().DoesColumnExist("foo", "id"));
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }
}

TEST_F(SQLConnectionTest, ErrorCallback) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER UNIQUE)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO foo (id) VALUES (12)"));

  int error = SQLITE_OK;
  {
    sql::ScopedErrorCallback sec(
        &db(), base::Bind(&sql::CaptureErrorCallback, &error));
    EXPECT_FALSE(db().Execute("INSERT INTO foo (id) VALUES (12)"));

    // Later versions of SQLite throw SQLITE_CONSTRAINT_UNIQUE.  The specific
    // sub-error isn't really important.
    EXPECT_EQ(SQLITE_CONSTRAINT, (error&0xff));
  }

  // Callback is no longer in force due to reset.
  {
    error = SQLITE_OK;
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CONSTRAINT);
    ASSERT_FALSE(db().Execute("INSERT INTO foo (id) VALUES (12)"));
    ASSERT_TRUE(expecter.SawExpectedErrors());
    EXPECT_EQ(SQLITE_OK, error);
  }

  // base::Bind() can curry arguments to be passed by const reference
  // to the callback function.  If the callback function calls
  // re/set_error_callback(), the storage for those arguments can be
  // deleted while the callback function is still executing.
  //
  // RefCounter() counts how many objects are live using an external
  // count.  The same counter is passed to the callback, so that it
  // can check directly even if the RefCounter object is no longer
  // live.
  {
    size_t count = 0;
    sql::ScopedErrorCallback sec(
        &db(), base::Bind(&ErrorCallbackSetHelper,
                          &db(), &count, RefCounter(&count)));

    EXPECT_FALSE(db().Execute("INSERT INTO foo (id) VALUES (12)"));
  }

  // Same test, but reset_error_callback() case.
  {
    size_t count = 0;
    sql::ScopedErrorCallback sec(
        &db(), base::Bind(&ErrorCallbackResetHelper,
                          &db(), &count, RefCounter(&count)));

    EXPECT_FALSE(db().Execute("INSERT INTO foo (id) VALUES (12)"));
  }
}

// Test that sql::Connection::Raze() results in a database without the
// tables from the original database.
TEST_F(SQLConnectionTest, Raze) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute("INSERT INTO foo (value) VALUES (12)"));

  int pragma_auto_vacuum = 0;
  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA auto_vacuum"));
    ASSERT_TRUE(s.Step());
    pragma_auto_vacuum = s.ColumnInt(0);
    ASSERT_TRUE(pragma_auto_vacuum == 0 || pragma_auto_vacuum == 1);
  }

  // If auto_vacuum is set, there's an extra page to maintain a freelist.
  const int kExpectedPageCount = 2 + pragma_auto_vacuum;

  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA page_count"));
    ASSERT_TRUE(s.Step());
    EXPECT_EQ(kExpectedPageCount, s.ColumnInt(0));
  }

  {
    sql::Statement s(db().GetUniqueStatement("SELECT * FROM sqlite_master"));
    ASSERT_TRUE(s.Step());
    EXPECT_EQ("table", s.ColumnString(0));
    EXPECT_EQ("foo", s.ColumnString(1));
    EXPECT_EQ("foo", s.ColumnString(2));
    // Table "foo" is stored in the last page of the file.
    EXPECT_EQ(kExpectedPageCount, s.ColumnInt(3));
    EXPECT_EQ(kCreateSql, s.ColumnString(4));
  }

  ASSERT_TRUE(db().Raze());

  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA page_count"));
    ASSERT_TRUE(s.Step());
    EXPECT_EQ(1, s.ColumnInt(0));
  }

  ASSERT_EQ(0, SqliteMasterCount(&db()));

  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA auto_vacuum"));
    ASSERT_TRUE(s.Step());
    // The new database has the same auto_vacuum as a fresh database.
    EXPECT_EQ(pragma_auto_vacuum, s.ColumnInt(0));
  }
}

// Test that Raze() maintains page_size.
TEST_F(SQLConnectionTest, RazePageSize) {
  // Fetch the default page size and double it for use in this test.
  // Scoped to release statement before Close().
  int default_page_size = 0;
  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA page_size"));
    ASSERT_TRUE(s.Step());
    default_page_size = s.ColumnInt(0);
  }
  ASSERT_GT(default_page_size, 0);
  const int kPageSize = 2 * default_page_size;

  // Re-open the database to allow setting the page size.
  db().Close();
  db().set_page_size(kPageSize);
  ASSERT_TRUE(db().Open(db_path()));

  // page_size should match the indicated value.
  sql::Statement s(db().GetUniqueStatement("PRAGMA page_size"));
  ASSERT_TRUE(s.Step());
  ASSERT_EQ(kPageSize, s.ColumnInt(0));

  // After raze, page_size should still match the indicated value.
  ASSERT_TRUE(db().Raze());
  s.Reset(true);
  ASSERT_TRUE(s.Step());
  ASSERT_EQ(kPageSize, s.ColumnInt(0));
}

// Test that Raze() results are seen in other connections.
TEST_F(SQLConnectionTest, RazeMultiple) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));

  sql::Connection other_db;
  ASSERT_TRUE(other_db.Open(db_path()));

  // Check that the second connection sees the table.
  ASSERT_EQ(1, SqliteMasterCount(&other_db));

  ASSERT_TRUE(db().Raze());

  // The second connection sees the updated database.
  ASSERT_EQ(0, SqliteMasterCount(&other_db));
}

// TODO(erg): Enable this in the next patch once I add locking.
#if !defined(MOJO_APPTEST_IMPL)
TEST_F(SQLConnectionTest, RazeLocked) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));

  // Open a transaction and write some data in a second connection.
  // This will acquire a PENDING or EXCLUSIVE transaction, which will
  // cause the raze to fail.
  sql::Connection other_db;
  ASSERT_TRUE(other_db.Open(db_path()));
  ASSERT_TRUE(other_db.BeginTransaction());
  const char* kInsertSql = "INSERT INTO foo VALUES (1, 'data')";
  ASSERT_TRUE(other_db.Execute(kInsertSql));

  ASSERT_FALSE(db().Raze());

  // Works after COMMIT.
  ASSERT_TRUE(other_db.CommitTransaction());
  ASSERT_TRUE(db().Raze());

  // Re-create the database.
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kInsertSql));

  // An unfinished read transaction in the other connection also
  // blocks raze.
  const char *kQuery = "SELECT COUNT(*) FROM foo";
  sql::Statement s(other_db.GetUniqueStatement(kQuery));
  ASSERT_TRUE(s.Step());
  ASSERT_FALSE(db().Raze());

  // Complete the statement unlocks the database.
  ASSERT_FALSE(s.Step());
  ASSERT_TRUE(db().Raze());
}
#endif

// Verify that Raze() can handle an empty file.  SQLite should treat
// this as an empty database.
TEST_F(SQLConnectionTest, RazeEmptyDB) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  db().Close();

  TruncateDatabase();

  ASSERT_TRUE(db().Open(db_path()));
  ASSERT_TRUE(db().Raze());
  EXPECT_EQ(0, SqliteMasterCount(&db()));
}

// Verify that Raze() can handle a file of junk.
TEST_F(SQLConnectionTest, RazeNOTADB) {
  db().Close();
  sql::Connection::Delete(db_path());
  ASSERT_FALSE(GetPathExists(db_path()));

  WriteJunkToDatabase(SQLTestBase::TYPE_OVERWRITE_AND_TRUNCATE);
  ASSERT_TRUE(GetPathExists(db_path()));

  // SQLite will successfully open the handle, but fail when running PRAGMA
  // statements that access the database.
  {
    sql::test::ScopedErrorExpecter expecter;

    // Earlier versions of Chromium compiled against SQLite 3.6.7.3, which
    // returned SQLITE_IOERR_SHORT_READ in this case.  Some platforms may still
    // compile against an earlier SQLite via USE_SYSTEM_SQLITE.
    if (expecter.SQLiteLibVersionNumber() < 3008005) {
      expecter.ExpectError(SQLITE_IOERR_SHORT_READ);
    } else {
      expecter.ExpectError(SQLITE_NOTADB);
    }

    EXPECT_TRUE(db().Open(db_path()));
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }
  EXPECT_TRUE(db().Raze());
  db().Close();

  // Now empty, the open should open an empty database.
  EXPECT_TRUE(db().Open(db_path()));
  EXPECT_EQ(0, SqliteMasterCount(&db()));
}

// Verify that Raze() can handle a database overwritten with garbage.
TEST_F(SQLConnectionTest, RazeNOTADB2) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_EQ(1, SqliteMasterCount(&db()));
  db().Close();

  WriteJunkToDatabase(SQLTestBase::TYPE_OVERWRITE);

  // SQLite will successfully open the handle, but will fail with
  // SQLITE_NOTADB on pragma statemenets which attempt to read the
  // corrupted header.
  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_NOTADB);
    EXPECT_TRUE(db().Open(db_path()));
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }
  EXPECT_TRUE(db().Raze());
  db().Close();

  // Now empty, the open should succeed with an empty database.
  EXPECT_TRUE(db().Open(db_path()));
  EXPECT_EQ(0, SqliteMasterCount(&db()));
}

// Test that a callback from Open() can raze the database.  This is
// essential for cases where the Open() can fail entirely, so the
// Raze() cannot happen later.  Additionally test that when the
// callback does this during Open(), the open is retried and succeeds.
TEST_F(SQLConnectionTest, RazeCallbackReopen) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_EQ(1, SqliteMasterCount(&db()));
  db().Close();

  // Corrupt the database so that nothing works, including PRAGMAs.
  ASSERT_TRUE(CorruptSizeInHeaderOfDB());

  // Open() will succeed, even though the PRAGMA calls within will
  // fail with SQLITE_CORRUPT, as will this PRAGMA.
  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CORRUPT);
    ASSERT_TRUE(db().Open(db_path()));
    ASSERT_FALSE(db().Execute("PRAGMA auto_vacuum"));
    db().Close();
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }

  db().set_error_callback(base::Bind(&SQLConnectionTest::RazeErrorCallback,
                                     base::Unretained(this),
                                     SQLITE_CORRUPT));

  // When the PRAGMA calls in Open() raise SQLITE_CORRUPT, the error
  // callback will call RazeAndClose().  Open() will then fail and be
  // retried.  The second Open() on the empty database will succeed
  // cleanly.
  ASSERT_TRUE(db().Open(db_path()));
  ASSERT_TRUE(db().Execute("PRAGMA auto_vacuum"));
  EXPECT_EQ(0, SqliteMasterCount(&db()));
}

// Basic test of RazeAndClose() operation.
TEST_F(SQLConnectionTest, RazeAndClose) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  const char* kPopulateSql = "INSERT INTO foo (value) VALUES (12)";

  // Test that RazeAndClose() closes the database, and that the
  // database is empty when re-opened.
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kPopulateSql));
  ASSERT_TRUE(db().RazeAndClose());
  ASSERT_FALSE(db().is_open());
  db().Close();
  ASSERT_TRUE(db().Open(db_path()));
  ASSERT_EQ(0, SqliteMasterCount(&db()));

  // Test that RazeAndClose() can break transactions.
  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kPopulateSql));
  ASSERT_TRUE(db().BeginTransaction());
  ASSERT_TRUE(db().RazeAndClose());
  ASSERT_FALSE(db().is_open());
  ASSERT_FALSE(db().CommitTransaction());
  db().Close();
  ASSERT_TRUE(db().Open(db_path()));
  ASSERT_EQ(0, SqliteMasterCount(&db()));
}

// Test that various operations fail without crashing after
// RazeAndClose().
TEST_F(SQLConnectionTest, RazeAndCloseDiagnostics) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  const char* kPopulateSql = "INSERT INTO foo (value) VALUES (12)";
  const char* kSimpleSql = "SELECT 1";

  ASSERT_TRUE(db().Execute(kCreateSql));
  ASSERT_TRUE(db().Execute(kPopulateSql));

  // Test baseline expectations.
  db().Preload();
  ASSERT_TRUE(db().DoesTableExist("foo"));
  ASSERT_TRUE(db().IsSQLValid(kSimpleSql));
  ASSERT_EQ(SQLITE_OK, db().ExecuteAndReturnErrorCode(kSimpleSql));
  ASSERT_TRUE(db().Execute(kSimpleSql));
  ASSERT_TRUE(db().is_open());
  {
    sql::Statement s(db().GetUniqueStatement(kSimpleSql));
    ASSERT_TRUE(s.Step());
  }
  {
    sql::Statement s(db().GetCachedStatement(SQL_FROM_HERE, kSimpleSql));
    ASSERT_TRUE(s.Step());
  }
  ASSERT_TRUE(db().BeginTransaction());
  ASSERT_TRUE(db().CommitTransaction());
  ASSERT_TRUE(db().BeginTransaction());
  db().RollbackTransaction();

  ASSERT_TRUE(db().RazeAndClose());

  // At this point, they should all fail, but not crash.
  db().Preload();
  ASSERT_FALSE(db().DoesTableExist("foo"));
  ASSERT_FALSE(db().IsSQLValid(kSimpleSql));
  ASSERT_EQ(SQLITE_ERROR, db().ExecuteAndReturnErrorCode(kSimpleSql));
  ASSERT_FALSE(db().Execute(kSimpleSql));
  ASSERT_FALSE(db().is_open());
  {
    sql::Statement s(db().GetUniqueStatement(kSimpleSql));
    ASSERT_FALSE(s.Step());
  }
  {
    sql::Statement s(db().GetCachedStatement(SQL_FROM_HERE, kSimpleSql));
    ASSERT_FALSE(s.Step());
  }
  ASSERT_FALSE(db().BeginTransaction());
  ASSERT_FALSE(db().CommitTransaction());
  ASSERT_FALSE(db().BeginTransaction());
  db().RollbackTransaction();

  // Close normally to reset the poisoned flag.
  db().Close();

  // DEATH tests not supported on Android or iOS.
#if !defined(OS_ANDROID) && !defined(OS_IOS)
  // Once the real Close() has been called, various calls enforce API
  // usage by becoming fatal in debug mode.  Since DEATH tests are
  // expensive, just test one of them.
  if (DLOG_IS_ON(FATAL)) {
    ASSERT_DEATH({
        db().IsSQLValid(kSimpleSql);
      }, "Illegal use of connection without a db");
  }
#endif
}

// TODO(shess): Spin up a background thread to hold other_db, to more
// closely match real life.  That would also allow testing
// RazeWithTimeout().

#if defined(OS_ANDROID)
TEST_F(SQLConnectionTest, SetTempDirForSQL) {

  sql::MetaTable meta_table;
  // Below call needs a temporary directory in sqlite3
  // On Android, it can pass only when the temporary directory is set.
  // Otherwise, sqlite3 doesn't find the correct directory to store
  // temporary files and will report the error 'unable to open
  // database file'.
  ASSERT_TRUE(meta_table.Init(&db(), 4, 4));
}
#endif

TEST_F(SQLConnectionTest, Delete) {
  EXPECT_TRUE(db().Execute("CREATE TABLE x (x)"));
  db().Close();

  // Should have both a main database file and a journal file because
  // of journal_mode TRUNCATE.
  base::FilePath journal(db_path().value() + FILE_PATH_LITERAL("-journal"));
  ASSERT_TRUE(GetPathExists(db_path()));
  ASSERT_TRUE(GetPathExists(journal));

  sql::Connection::Delete(db_path());
  EXPECT_FALSE(GetPathExists(db_path()));
  EXPECT_FALSE(GetPathExists(journal));
}

// This test manually sets on disk permissions; this doesn't apply to the mojo
// fork.
#if defined(OS_POSIX) && !defined(MOJO_APPTEST_IMPL)
// Test that set_restrict_to_user() trims database permissions so that
// only the owner (and root) can read.
TEST_F(SQLConnectionTest, UserPermission) {
  // If the bots all had a restrictive umask setting such that
  // databases are always created with only the owner able to read
  // them, then the code could break without breaking the tests.
  // Temporarily provide a more permissive umask.
  db().Close();
  sql::Connection::Delete(db_path());
  ASSERT_FALSE(GetPathExists(db_path()));
  ScopedUmaskSetter permissive_umask(S_IWGRP | S_IWOTH);
  ASSERT_TRUE(db().Open(db_path()));

  // Cause the journal file to be created.  If the default
  // journal_mode is changed back to DELETE, then parts of this test
  // will need to be updated.
  EXPECT_TRUE(db().Execute("CREATE TABLE x (x)"));

  base::FilePath journal(db_path().value() + FILE_PATH_LITERAL("-journal"));
  int mode;

  // Given a permissive umask, the database is created with permissive
  // read access for the database and journal.
  ASSERT_TRUE(GetPathExists(db_path()));
  ASSERT_TRUE(GetPathExists(journal));
  mode = base::FILE_PERMISSION_MASK;
  EXPECT_TRUE(base::GetPosixFilePermissions(db_path(), &mode));
  ASSERT_NE((mode & base::FILE_PERMISSION_USER_MASK), mode);
  mode = base::FILE_PERMISSION_MASK;
  EXPECT_TRUE(base::GetPosixFilePermissions(journal, &mode));
  ASSERT_NE((mode & base::FILE_PERMISSION_USER_MASK), mode);

  // Re-open with restricted permissions and verify that the modes
  // changed for both the main database and the journal.
  db().Close();
  db().set_restrict_to_user();
  ASSERT_TRUE(db().Open(db_path()));
  ASSERT_TRUE(GetPathExists(db_path()));
  ASSERT_TRUE(GetPathExists(journal));
  mode = base::FILE_PERMISSION_MASK;
  EXPECT_TRUE(base::GetPosixFilePermissions(db_path(), &mode));
  ASSERT_EQ((mode & base::FILE_PERMISSION_USER_MASK), mode);
  mode = base::FILE_PERMISSION_MASK;
  EXPECT_TRUE(base::GetPosixFilePermissions(journal, &mode));
  ASSERT_EQ((mode & base::FILE_PERMISSION_USER_MASK), mode);

  // Delete and re-create the database, the restriction should still apply.
  db().Close();
  sql::Connection::Delete(db_path());
  ASSERT_TRUE(db().Open(db_path()));
  ASSERT_TRUE(GetPathExists(db_path()));
  ASSERT_FALSE(GetPathExists(journal));
  mode = base::FILE_PERMISSION_MASK;
  EXPECT_TRUE(base::GetPosixFilePermissions(db_path(), &mode));
  ASSERT_EQ((mode & base::FILE_PERMISSION_USER_MASK), mode);

  // Verify that journal creation inherits the restriction.
  EXPECT_TRUE(db().Execute("CREATE TABLE x (x)"));
  ASSERT_TRUE(GetPathExists(journal));
  mode = base::FILE_PERMISSION_MASK;
  EXPECT_TRUE(base::GetPosixFilePermissions(journal, &mode));
  ASSERT_EQ((mode & base::FILE_PERMISSION_USER_MASK), mode);
}
#endif  // defined(OS_POSIX)

// Test that errors start happening once Poison() is called.
TEST_F(SQLConnectionTest, Poison) {
  EXPECT_TRUE(db().Execute("CREATE TABLE x (x)"));

  // Before the Poison() call, things generally work.
  EXPECT_TRUE(db().IsSQLValid("INSERT INTO x VALUES ('x')"));
  EXPECT_TRUE(db().Execute("INSERT INTO x VALUES ('x')"));
  {
    sql::Statement s(db().GetUniqueStatement("SELECT COUNT(*) FROM x"));
    ASSERT_TRUE(s.is_valid());
    ASSERT_TRUE(s.Step());
  }

  // Get a statement which is valid before and will exist across Poison().
  sql::Statement valid_statement(
      db().GetUniqueStatement("SELECT COUNT(*) FROM sqlite_master"));
  ASSERT_TRUE(valid_statement.is_valid());
  ASSERT_TRUE(valid_statement.Step());
  valid_statement.Reset(true);

  db().Poison();

  // After the Poison() call, things fail.
  EXPECT_FALSE(db().IsSQLValid("INSERT INTO x VALUES ('x')"));
  EXPECT_FALSE(db().Execute("INSERT INTO x VALUES ('x')"));
  {
    sql::Statement s(db().GetUniqueStatement("SELECT COUNT(*) FROM x"));
    ASSERT_FALSE(s.is_valid());
    ASSERT_FALSE(s.Step());
  }

  // The existing statement has become invalid.
  ASSERT_FALSE(valid_statement.is_valid());
  ASSERT_FALSE(valid_statement.Step());

  // Test that poisoning the database during a transaction works (with errors).
  // RazeErrorCallback() poisons the database, the extra COMMIT causes
  // CommitTransaction() to throw an error while commiting.
  db().set_error_callback(base::Bind(&SQLConnectionTest::RazeErrorCallback,
                                     base::Unretained(this),
                                     SQLITE_ERROR));
  db().Close();
  ASSERT_TRUE(db().Open(db_path()));
  EXPECT_TRUE(db().BeginTransaction());
  EXPECT_TRUE(db().Execute("INSERT INTO x VALUES ('x')"));
  EXPECT_TRUE(db().Execute("COMMIT"));
  EXPECT_FALSE(db().CommitTransaction());
}

// Test attaching and detaching databases from the connection.
TEST_F(SQLConnectionTest, Attach) {
  EXPECT_TRUE(db().Execute("CREATE TABLE foo (a, b)"));

  // Create a database to attach to.
  base::FilePath attach_path =
      db_path().DirName().AppendASCII("SQLConnectionAttach.db");
  const char kAttachmentPoint[] = "other";
  {
    sql::Connection other_db;
    ASSERT_TRUE(other_db.Open(attach_path));
    EXPECT_TRUE(other_db.Execute("CREATE TABLE bar (a, b)"));
    EXPECT_TRUE(other_db.Execute("INSERT INTO bar VALUES ('hello', 'world')"));
  }

  // Cannot see the attached database, yet.
  EXPECT_FALSE(db().IsSQLValid("SELECT count(*) from other.bar"));

  // Attach fails in a transaction.
  EXPECT_TRUE(db().BeginTransaction());
  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_ERROR);
    EXPECT_FALSE(db().AttachDatabase(attach_path, kAttachmentPoint));
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }

  // Attach succeeds when the transaction is closed.
  db().RollbackTransaction();
  EXPECT_TRUE(db().AttachDatabase(attach_path, kAttachmentPoint));
  EXPECT_TRUE(db().IsSQLValid("SELECT count(*) from other.bar"));

  // Queries can touch both databases.
  EXPECT_TRUE(db().Execute("INSERT INTO foo SELECT a, b FROM other.bar"));
  {
    sql::Statement s(db().GetUniqueStatement("SELECT COUNT(*) FROM foo"));
    ASSERT_TRUE(s.Step());
    EXPECT_EQ(1, s.ColumnInt(0));
  }

  // Detach also fails in a transaction.
  EXPECT_TRUE(db().BeginTransaction());
  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_ERROR);
    EXPECT_FALSE(db().DetachDatabase(kAttachmentPoint));
    EXPECT_TRUE(db().IsSQLValid("SELECT count(*) from other.bar"));
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }

  // Detach succeeds outside of a transaction.
  db().RollbackTransaction();
  EXPECT_TRUE(db().DetachDatabase(kAttachmentPoint));

  EXPECT_FALSE(db().IsSQLValid("SELECT count(*) from other.bar"));
}

TEST_F(SQLConnectionTest, Basic_QuickIntegrityCheck) {
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  EXPECT_TRUE(db().QuickIntegrityCheck());
  db().Close();

  ASSERT_TRUE(CorruptSizeInHeaderOfDB());

  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CORRUPT);
    ASSERT_TRUE(db().Open(db_path()));
    EXPECT_FALSE(db().QuickIntegrityCheck());
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }
}

TEST_F(SQLConnectionTest, Basic_FullIntegrityCheck) {
  const std::string kOk("ok");
  std::vector<std::string> messages;

  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  ASSERT_TRUE(db().Execute(kCreateSql));
  EXPECT_TRUE(db().FullIntegrityCheck(&messages));
  EXPECT_EQ(1u, messages.size());
  EXPECT_EQ(kOk, messages[0]);
  db().Close();

  ASSERT_TRUE(CorruptSizeInHeaderOfDB());

  {
    sql::test::ScopedErrorExpecter expecter;
    expecter.ExpectError(SQLITE_CORRUPT);
    ASSERT_TRUE(db().Open(db_path()));
    EXPECT_TRUE(db().FullIntegrityCheck(&messages));
    EXPECT_LT(1u, messages.size());
    EXPECT_NE(kOk, messages[0]);
    ASSERT_TRUE(expecter.SawExpectedErrors());
  }

  // TODO(shess): CorruptTableOrIndex could be used to produce a
  // file that would pass the quick check and fail the full check.
}

// Test Sqlite.Stats histogram for execute-oriented calls.
TEST_F(SQLConnectionTest, EventsExecute) {
  // Re-open with histogram tag.
  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().Open(db_path()));

  // Open() uses Execute() extensively, don't track those calls.
  base::HistogramTester tester;

  const char kHistogramName[] = "Sqlite.Stats.Test";
  const char kGlobalHistogramName[] = "Sqlite.Stats";

  ASSERT_TRUE(db().BeginTransaction());
  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  EXPECT_TRUE(db().Execute(kCreateSql));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (10, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (11, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (12, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (13, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (14, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (15, 'text');"
                           "INSERT INTO foo VALUES (16, 'text');"
                           "INSERT INTO foo VALUES (17, 'text');"
                           "INSERT INTO foo VALUES (18, 'text');"
                           "INSERT INTO foo VALUES (19, 'text')"));
  ASSERT_TRUE(db().CommitTransaction());
  ASSERT_TRUE(db().BeginTransaction());
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (20, 'text')"));
  db().RollbackTransaction();
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (20, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (21, 'text')"));

  // The create, 5 inserts, multi-statement insert, rolled-back insert, 2
  // inserts outside transaction.
  tester.ExpectBucketCount(kHistogramName, sql::Connection::EVENT_EXECUTE, 10);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_EXECUTE, 10);

  // All of the executes, with the multi-statement inserts broken out, plus one
  // for each begin, commit, and rollback.
  tester.ExpectBucketCount(kHistogramName,
                           sql::Connection::EVENT_STATEMENT_RUN, 18);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_STATEMENT_RUN, 18);

  tester.ExpectBucketCount(kHistogramName,
                           sql::Connection::EVENT_STATEMENT_ROWS, 0);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_STATEMENT_ROWS, 0);
  tester.ExpectBucketCount(kHistogramName,
                           sql::Connection::EVENT_STATEMENT_SUCCESS, 18);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_STATEMENT_SUCCESS, 18);

  // The 2 inserts outside the transaction.
  tester.ExpectBucketCount(kHistogramName,
                           sql::Connection::EVENT_CHANGES_AUTOCOMMIT, 2);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_CHANGES_AUTOCOMMIT, 2);

  // 11 inserts inside transactions.
  tester.ExpectBucketCount(kHistogramName, sql::Connection::EVENT_CHANGES, 11);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_CHANGES, 11);

  tester.ExpectBucketCount(kHistogramName, sql::Connection::EVENT_BEGIN, 2);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_BEGIN, 2);
  tester.ExpectBucketCount(kHistogramName, sql::Connection::EVENT_COMMIT, 1);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_COMMIT, 1);
  tester.ExpectBucketCount(kHistogramName, sql::Connection::EVENT_ROLLBACK, 1);
  tester.ExpectBucketCount(kGlobalHistogramName,
                           sql::Connection::EVENT_ROLLBACK, 1);
}

// Test Sqlite.Stats histogram for prepared statements.
TEST_F(SQLConnectionTest, EventsStatement) {
  // Re-open with histogram tag.
  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().Open(db_path()));

  const char kHistogramName[] = "Sqlite.Stats.Test";
  const char kGlobalHistogramName[] = "Sqlite.Stats";

  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  EXPECT_TRUE(db().Execute(kCreateSql));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (10, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (11, 'text')"));
  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (12, 'text')"));

  {
    base::HistogramTester tester;

    {
      sql::Statement s(db().GetUniqueStatement("SELECT value FROM foo"));
      while (s.Step()) {
      }
    }

    tester.ExpectBucketCount(kHistogramName,
                             sql::Connection::EVENT_STATEMENT_RUN, 1);
    tester.ExpectBucketCount(kGlobalHistogramName,
                             sql::Connection::EVENT_STATEMENT_RUN, 1);
    tester.ExpectBucketCount(kHistogramName,
                             sql::Connection::EVENT_STATEMENT_ROWS, 3);
    tester.ExpectBucketCount(kGlobalHistogramName,
                             sql::Connection::EVENT_STATEMENT_ROWS, 3);
    tester.ExpectBucketCount(kHistogramName,
                             sql::Connection::EVENT_STATEMENT_SUCCESS, 1);
    tester.ExpectBucketCount(kGlobalHistogramName,
                             sql::Connection::EVENT_STATEMENT_SUCCESS, 1);
  }

  {
    base::HistogramTester tester;

    {
      sql::Statement s(db().GetUniqueStatement(
          "SELECT value FROM foo WHERE id > 10"));
      while (s.Step()) {
      }
    }

    tester.ExpectBucketCount(kHistogramName,
                             sql::Connection::EVENT_STATEMENT_RUN, 1);
    tester.ExpectBucketCount(kGlobalHistogramName,
                             sql::Connection::EVENT_STATEMENT_RUN, 1);
    tester.ExpectBucketCount(kHistogramName,
                             sql::Connection::EVENT_STATEMENT_ROWS, 2);
    tester.ExpectBucketCount(kGlobalHistogramName,
                             sql::Connection::EVENT_STATEMENT_ROWS, 2);
    tester.ExpectBucketCount(kHistogramName,
                             sql::Connection::EVENT_STATEMENT_SUCCESS, 1);
    tester.ExpectBucketCount(kGlobalHistogramName,
                             sql::Connection::EVENT_STATEMENT_SUCCESS, 1);
  }
}

// Read-only query allocates time to QueryTime, but not others.
TEST_F(SQLConnectionTest, TimeQuery) {
  // Re-open with histogram tag.  Use an in-memory database to minimize variance
  // due to filesystem.
  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().OpenInMemory());

  sql::test::ScopedMockTimeSource time_mock(db());

  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  EXPECT_TRUE(db().Execute(kCreateSql));

  // Function to inject pauses into statements.
  sql::test::ScopedScalarFunction scoper(
      db(), "milliadjust", 1, base::Bind(&sqlite_adjust_millis, &time_mock));

  base::HistogramTester tester;

  EXPECT_TRUE(db().Execute("SELECT milliadjust(10)"));

  std::unique_ptr<base::HistogramSamples> samples(
      tester.GetHistogramSamplesSinceCreation(kQueryTime));
  ASSERT_TRUE(samples);
  // 10 for the adjust, 1 for the measurement.
  EXPECT_EQ(11, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kUpdateTime);
  EXPECT_EQ(0, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kCommitTime);
  EXPECT_EQ(0, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kAutoCommitTime);
  EXPECT_EQ(0, samples->sum());
}

// Autocommit update allocates time to QueryTime, UpdateTime, and
// AutoCommitTime.
TEST_F(SQLConnectionTest, TimeUpdateAutocommit) {
  // Re-open with histogram tag.  Use an in-memory database to minimize variance
  // due to filesystem.
  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().OpenInMemory());

  sql::test::ScopedMockTimeSource time_mock(db());

  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  EXPECT_TRUE(db().Execute(kCreateSql));

  // Function to inject pauses into statements.
  sql::test::ScopedScalarFunction scoper(
      db(), "milliadjust", 1, base::Bind(&sqlite_adjust_millis, &time_mock));

  base::HistogramTester tester;

  EXPECT_TRUE(db().Execute("INSERT INTO foo VALUES (10, milliadjust(10))"));

  std::unique_ptr<base::HistogramSamples> samples(
      tester.GetHistogramSamplesSinceCreation(kQueryTime));
  ASSERT_TRUE(samples);
  // 10 for the adjust, 1 for the measurement.
  EXPECT_EQ(11, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kUpdateTime);
  ASSERT_TRUE(samples);
  // 10 for the adjust, 1 for the measurement.
  EXPECT_EQ(11, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kCommitTime);
  EXPECT_EQ(0, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kAutoCommitTime);
  ASSERT_TRUE(samples);
  // 10 for the adjust, 1 for the measurement.
  EXPECT_EQ(11, samples->sum());
}

// Update with explicit transaction allocates time to QueryTime, UpdateTime, and
// CommitTime.
TEST_F(SQLConnectionTest, TimeUpdateTransaction) {
  // Re-open with histogram tag.  Use an in-memory database to minimize variance
  // due to filesystem.
  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().OpenInMemory());

  sql::test::ScopedMockTimeSource time_mock(db());

  const char* kCreateSql = "CREATE TABLE foo (id INTEGER PRIMARY KEY, value)";
  EXPECT_TRUE(db().Execute(kCreateSql));

  // Function to inject pauses into statements.
  sql::test::ScopedScalarFunction scoper(
      db(), "milliadjust", 1, base::Bind(&sqlite_adjust_millis, &time_mock));

  base::HistogramTester tester;

  {
    // Make the commit slow.
    sql::test::ScopedCommitHook scoped_hook(
        db(), base::Bind(adjust_commit_hook, &time_mock, 100));
    ASSERT_TRUE(db().BeginTransaction());
    EXPECT_TRUE(db().Execute(
        "INSERT INTO foo VALUES (11, milliadjust(10))"));
    EXPECT_TRUE(db().Execute(
        "UPDATE foo SET value = milliadjust(10) WHERE id = 11"));
    EXPECT_TRUE(db().CommitTransaction());
  }

  std::unique_ptr<base::HistogramSamples> samples(
      tester.GetHistogramSamplesSinceCreation(kQueryTime));
  ASSERT_TRUE(samples);
  // 10 for insert adjust, 10 for update adjust, 100 for commit adjust, 1 for
  // measuring each of BEGIN, INSERT, UPDATE, and COMMIT.
  EXPECT_EQ(124, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kUpdateTime);
  ASSERT_TRUE(samples);
  // 10 for insert adjust, 10 for update adjust, 100 for commit adjust, 1 for
  // measuring each of INSERT, UPDATE, and COMMIT.
  EXPECT_EQ(123, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kCommitTime);
  ASSERT_TRUE(samples);
  // 100 for commit adjust, 1 for measuring COMMIT.
  EXPECT_EQ(101, samples->sum());

  samples = tester.GetHistogramSamplesSinceCreation(kAutoCommitTime);
  EXPECT_EQ(0, samples->sum());
}

TEST_F(SQLConnectionTest, OnMemoryDump) {
  base::trace_event::MemoryDumpArgs args = {
      base::trace_event::MemoryDumpLevelOfDetail::DETAILED};
  base::trace_event::ProcessMemoryDump pmd(nullptr, args);
  ASSERT_TRUE(db().memory_dump_provider_->OnMemoryDump(args, &pmd));
  EXPECT_GE(pmd.allocator_dumps().size(), 1u);
}

// Test that the functions to collect diagnostic data run to completion, without
// worrying too much about what they generate (since that will change).
TEST_F(SQLConnectionTest, CollectDiagnosticInfo) {
  // NOTE(shess): Mojo doesn't support everything CollectCorruptionInfo() uses,
  // but it's not really clear if adding support would be useful.
#if !defined(MOJO_APPTEST_IMPL)
  const std::string corruption_info = db().CollectCorruptionInfo();
  EXPECT_NE(std::string::npos, corruption_info.find("SQLITE_CORRUPT"));
  EXPECT_NE(std::string::npos, corruption_info.find("integrity_check"));
#endif

  // A statement to see in the results.
  const char* kSimpleSql = "SELECT 'mountain'";
  Statement s(db().GetCachedStatement(SQL_FROM_HERE, kSimpleSql));

  // Error includes the statement.
  const std::string readonly_info = db().CollectErrorInfo(SQLITE_READONLY, &s);
  EXPECT_NE(std::string::npos, readonly_info.find(kSimpleSql));

  // Some other error doesn't include the statment.
  // TODO(shess): This is weak.
  const std::string full_info = db().CollectErrorInfo(SQLITE_FULL, NULL);
  EXPECT_EQ(std::string::npos, full_info.find(kSimpleSql));

  // A table to see in the SQLITE_ERROR results.
  EXPECT_TRUE(db().Execute("CREATE TABLE volcano (x)"));

  // Version info to see in the SQLITE_ERROR results.
  sql::MetaTable meta_table;
  ASSERT_TRUE(meta_table.Init(&db(), 4, 4));

  const std::string error_info = db().CollectErrorInfo(SQLITE_ERROR, &s);
  EXPECT_NE(std::string::npos, error_info.find(kSimpleSql));
  EXPECT_NE(std::string::npos, error_info.find("volcano"));
  EXPECT_NE(std::string::npos, error_info.find("version: 4"));
}

#if !defined(MOJO_APPTEST_IMPL)
TEST_F(SQLConnectionTest, RegisterIntentToUpload) {
  base::FilePath breadcrumb_path(
      db_path().DirName().Append(FILE_PATH_LITERAL("sqlite-diag")));

  // No stale diagnostic store.
  ASSERT_TRUE(!base::PathExists(breadcrumb_path));

  // The histogram tag is required to enable diagnostic features.
  EXPECT_FALSE(db().RegisterIntentToUpload());
  EXPECT_TRUE(!base::PathExists(breadcrumb_path));

  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().Open(db_path()));

  // Should signal upload only once.
  EXPECT_TRUE(db().RegisterIntentToUpload());
  EXPECT_TRUE(base::PathExists(breadcrumb_path));
  EXPECT_FALSE(db().RegisterIntentToUpload());

  // Changing the histogram tag should allow new upload to succeed.
  db().Close();
  db().set_histogram_tag("NewTest");
  ASSERT_TRUE(db().Open(db_path()));
  EXPECT_TRUE(db().RegisterIntentToUpload());
  EXPECT_FALSE(db().RegisterIntentToUpload());

  // Old tag is still prevented.
  db().Close();
  db().set_histogram_tag("Test");
  ASSERT_TRUE(db().Open(db_path()));
  EXPECT_FALSE(db().RegisterIntentToUpload());
}
#endif  // !defined(MOJO_APPTEST_IMPL)

// Test that a fresh database has mmap enabled by default, if mmap'ed I/O is
// enabled by SQLite.
TEST_F(SQLConnectionTest, MmapInitiallyEnabled) {
  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA mmap_size"));

    // SQLite doesn't have mmap support (perhaps an early iOS release).
    if (!s.Step())
      return;

    // If mmap I/O is not on, attempt to turn it on.  If that succeeds, then
    // Open() should have turned it on.  If mmap support is disabled, 0 is
    // returned.  If the VFS does not understand SQLITE_FCNTL_MMAP_SIZE (for
    // instance MojoVFS), -1 is returned.
    if (s.ColumnInt(0) <= 0) {
      ASSERT_TRUE(db().Execute("PRAGMA mmap_size = 1048576"));
      s.Reset(true);
      ASSERT_TRUE(s.Step());
      EXPECT_LE(s.ColumnInt(0), 0);
    }
  }

  // Test that explicit disable prevents mmap'ed I/O.
  db().Close();
  sql::Connection::Delete(db_path());
  db().set_mmap_disabled();
  ASSERT_TRUE(db().Open(db_path()));
  {
    sql::Statement s(db().GetUniqueStatement("PRAGMA mmap_size"));
    ASSERT_TRUE(s.Step());
    EXPECT_LE(s.ColumnInt(0), 0);
  }
}

TEST_F(SQLConnectionTest, GetAppropriateMmapSize) {
#if defined(OS_IOS) && defined(USE_SYSTEM_SQLITE)
  // Mmap is not supported on iOS9.
  if (!base::ios::IsRunningOnIOS10OrLater()) {
    ASSERT_EQ(0UL, db().GetAppropriateMmapSize());
    return;
  }
#endif

  const size_t kMmapAlot = 25 * 1024 * 1024;
  int64_t mmap_status = MetaTable::kMmapFailure;

  // If there is no meta table (as for a fresh database), assume that everything
  // should be mapped, and the status of the meta table is not affected.
  ASSERT_TRUE(!db().DoesTableExist("meta"));
  ASSERT_GT(db().GetAppropriateMmapSize(), kMmapAlot);
  ASSERT_TRUE(!db().DoesTableExist("meta"));

  // When the meta table is first created, it sets up to map everything.
  MetaTable().Init(&db(), 1, 1);
  ASSERT_TRUE(db().DoesTableExist("meta"));
  ASSERT_GT(db().GetAppropriateMmapSize(), kMmapAlot);
  ASSERT_TRUE(MetaTable::GetMmapStatus(&db(), &mmap_status));
  ASSERT_EQ(MetaTable::kMmapSuccess, mmap_status);

  // Failure status maps nothing.
  ASSERT_TRUE(db().Execute("REPLACE INTO meta VALUES ('mmap_status', -2)"));
  ASSERT_EQ(0UL, db().GetAppropriateMmapSize());

  // Re-initializing the meta table does not re-create the key if the table
  // already exists.
  ASSERT_TRUE(db().Execute("DELETE FROM meta WHERE key = 'mmap_status'"));
  MetaTable().Init(&db(), 1, 1);
  ASSERT_EQ(MetaTable::kMmapSuccess, mmap_status);
  ASSERT_TRUE(MetaTable::GetMmapStatus(&db(), &mmap_status));
  ASSERT_EQ(0, mmap_status);

  // With no key, map everything and create the key.
  // TODO(shess): This really should be "maps everything after validating it",
  // but that is more complicated to structure.
  ASSERT_GT(db().GetAppropriateMmapSize(), kMmapAlot);
  ASSERT_TRUE(MetaTable::GetMmapStatus(&db(), &mmap_status));
  ASSERT_EQ(MetaTable::kMmapSuccess, mmap_status);
}

// To prevent invalid SQL from accidentally shipping to production, prepared
// statements which fail to compile with SQLITE_ERROR call DLOG(FATAL).  This
// case cannot be suppressed with an error callback.
TEST_F(SQLConnectionTest, CompileError) {
  // DEATH tests not supported on Android or iOS.
#if !defined(OS_ANDROID) && !defined(OS_IOS)
  if (DLOG_IS_ON(FATAL)) {
    db().set_error_callback(base::Bind(&IgnoreErrorCallback));
    ASSERT_DEATH({
        db().GetUniqueStatement("SELECT x");
      }, "SQL compile error no such column: x");
  }
#endif
}

}  // namespace sql
