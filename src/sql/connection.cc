// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "sql/connection.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <utility>

#include "base/bind.h"
#include "base/debug/dump_without_crashing.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/format_macros.h"
#include "base/json/json_file_value_serializer.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/memory_dump_manager.h"
#include "sql/connection_memory_dump_provider.h"
#include "sql/meta_table.h"
#include "sql/statement.h"
#include "third_party/sqlite/sqlite3.h"

#if defined(OS_IOS) && defined(USE_SYSTEM_SQLITE)
#include "base/ios/ios_util.h"
#include "third_party/sqlite/src/ext/icu/sqliteicu.h"
#endif

namespace {

// Spin for up to a second waiting for the lock to clear when setting
// up the database.
// TODO(shess): Better story on this.  http://crbug.com/56559
const int kBusyTimeoutSeconds = 1;

class ScopedBusyTimeout {
 public:
  explicit ScopedBusyTimeout(sqlite3* db)
      : db_(db) {
  }
  ~ScopedBusyTimeout() {
    sqlite3_busy_timeout(db_, 0);
  }

  int SetTimeout(base::TimeDelta timeout) {
    DCHECK_LT(timeout.InMilliseconds(), INT_MAX);
    return sqlite3_busy_timeout(db_,
                                static_cast<int>(timeout.InMilliseconds()));
  }

 private:
  sqlite3* db_;
};

// Helper to "safely" enable writable_schema.  No error checking
// because it is reasonable to just forge ahead in case of an error.
// If turning it on fails, then most likely nothing will work, whereas
// if turning it off fails, it only matters if some code attempts to
// continue working with the database and tries to modify the
// sqlite_master table (none of our code does this).
class ScopedWritableSchema {
 public:
  explicit ScopedWritableSchema(sqlite3* db)
      : db_(db) {
    sqlite3_exec(db_, "PRAGMA writable_schema=1", NULL, NULL, NULL);
  }
  ~ScopedWritableSchema() {
    sqlite3_exec(db_, "PRAGMA writable_schema=0", NULL, NULL, NULL);
  }

 private:
  sqlite3* db_;
};

// Helper to wrap the sqlite3_backup_*() step of Raze().  Return
// SQLite error code from running the backup step.
int BackupDatabase(sqlite3* src, sqlite3* dst, const char* db_name) {
  DCHECK_NE(src, dst);
  sqlite3_backup* backup = sqlite3_backup_init(dst, db_name, src, db_name);
  if (!backup) {
    // Since this call only sets things up, this indicates a gross
    // error in SQLite.
    DLOG(FATAL) << "Unable to start sqlite3_backup(): " << sqlite3_errmsg(dst);
    return sqlite3_errcode(dst);
  }

  // -1 backs up the entire database.
  int rc = sqlite3_backup_step(backup, -1);
  int pages = sqlite3_backup_pagecount(backup);
  sqlite3_backup_finish(backup);

  // If successful, exactly one page should have been backed up.  If
  // this breaks, check this function to make sure assumptions aren't
  // being broken.
  if (rc == SQLITE_DONE)
    DCHECK_EQ(pages, 1);

  return rc;
}

// Be very strict on attachment point.  SQLite can handle a much wider
// character set with appropriate quoting, but Chromium code should
// just use clean names to start with.
bool ValidAttachmentPoint(const char* attachment_point) {
  for (size_t i = 0; attachment_point[i]; ++i) {
    if (!(base::IsAsciiDigit(attachment_point[i]) ||
          base::IsAsciiAlpha(attachment_point[i]) ||
          attachment_point[i] == '_')) {
      return false;
    }
  }
  return true;
}

void RecordSqliteMemory10Min() {
  const int64_t used = sqlite3_memory_used();
  UMA_HISTOGRAM_COUNTS("Sqlite.MemoryKB.TenMinutes", used / 1024);
}

void RecordSqliteMemoryHour() {
  const int64_t used = sqlite3_memory_used();
  UMA_HISTOGRAM_COUNTS("Sqlite.MemoryKB.OneHour", used / 1024);
}

void RecordSqliteMemoryDay() {
  const int64_t used = sqlite3_memory_used();
  UMA_HISTOGRAM_COUNTS("Sqlite.MemoryKB.OneDay", used / 1024);
}

void RecordSqliteMemoryWeek() {
  const int64_t used = sqlite3_memory_used();
  UMA_HISTOGRAM_COUNTS("Sqlite.MemoryKB.OneWeek", used / 1024);
}

// SQLite automatically calls sqlite3_initialize() lazily, but
// sqlite3_initialize() uses double-checked locking and thus can have
// data races.
//
// TODO(shess): Another alternative would be to have
// sqlite3_initialize() called as part of process bring-up.  If this
// is changed, remove the dynamic_annotations dependency in sql.gyp.
base::LazyInstance<base::Lock>::Leaky
    g_sqlite_init_lock = LAZY_INSTANCE_INITIALIZER;
void InitializeSqlite() {
  base::AutoLock lock(g_sqlite_init_lock.Get());
  static bool first_call = true;
  if (first_call) {
    sqlite3_initialize();

    // Schedule callback to record memory footprint histograms at 10m, 1h, and
    // 1d. There may not be a registered thread task runner in tests.
    if (base::ThreadTaskRunnerHandle::IsSet()) {
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, base::Bind(&RecordSqliteMemory10Min),
          base::TimeDelta::FromMinutes(10));
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, base::Bind(&RecordSqliteMemoryHour),
          base::TimeDelta::FromHours(1));
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, base::Bind(&RecordSqliteMemoryDay),
          base::TimeDelta::FromDays(1));
      base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
          FROM_HERE, base::Bind(&RecordSqliteMemoryWeek),
          base::TimeDelta::FromDays(7));
    }

    first_call = false;
  }
}

// Helper to get the sqlite3_file* associated with the "main" database.
int GetSqlite3File(sqlite3* db, sqlite3_file** file) {
  *file = NULL;
  int rc = sqlite3_file_control(db, NULL, SQLITE_FCNTL_FILE_POINTER, file);
  if (rc != SQLITE_OK)
    return rc;

  // TODO(shess): NULL in file->pMethods has been observed on android_dbg
  // content_unittests, even though it should not be possible.
  // http://crbug.com/329982
  if (!*file || !(*file)->pMethods)
    return SQLITE_ERROR;

  return rc;
}

// Convenience to get the sqlite3_file* and the size for the "main" database.
int GetSqlite3FileAndSize(sqlite3* db,
                          sqlite3_file** file, sqlite3_int64* db_size) {
  int rc = GetSqlite3File(db, file);
  if (rc != SQLITE_OK)
    return rc;

  return (*file)->pMethods->xFileSize(*file, db_size);
}

// This should match UMA_HISTOGRAM_MEDIUM_TIMES().
base::HistogramBase* GetMediumTimeHistogram(const std::string& name) {
  return base::Histogram::FactoryTimeGet(
      name,
      base::TimeDelta::FromMilliseconds(10),
      base::TimeDelta::FromMinutes(3),
      50,
      base::HistogramBase::kUmaTargetedHistogramFlag);
}

std::string AsUTF8ForSQL(const base::FilePath& path) {
#if defined(OS_WIN)
  return base::WideToUTF8(path.value());
#elif defined(OS_POSIX)
  return path.value();
#endif
}

}  // namespace

namespace sql {

// static
Connection::ErrorExpecterCallback* Connection::current_expecter_cb_ = NULL;

// static
bool Connection::IsExpectedSqliteError(int error) {
  if (!current_expecter_cb_)
    return false;
  return current_expecter_cb_->Run(error);
}

void Connection::ReportDiagnosticInfo(int extended_error, Statement* stmt) {
  AssertIOAllowed();

  std::string debug_info = GetDiagnosticInfo(extended_error, stmt);
  if (!debug_info.empty() && RegisterIntentToUpload()) {
    char debug_buf[2000];
    base::strlcpy(debug_buf, debug_info.c_str(), arraysize(debug_buf));
    base::debug::Alias(&debug_buf);

    base::debug::DumpWithoutCrashing();
  }
}

// static
void Connection::SetErrorExpecter(Connection::ErrorExpecterCallback* cb) {
  CHECK(current_expecter_cb_ == NULL);
  current_expecter_cb_ = cb;
}

// static
void Connection::ResetErrorExpecter() {
  CHECK(current_expecter_cb_);
  current_expecter_cb_ = NULL;
}

bool StatementID::operator<(const StatementID& other) const {
  if (number_ != other.number_)
    return number_ < other.number_;
  return strcmp(str_, other.str_) < 0;
}

Connection::StatementRef::StatementRef(Connection* connection,
                                       sqlite3_stmt* stmt,
                                       bool was_valid)
    : connection_(connection),
      stmt_(stmt),
      was_valid_(was_valid) {
  if (connection)
    connection_->StatementRefCreated(this);
}

Connection::StatementRef::~StatementRef() {
  if (connection_)
    connection_->StatementRefDeleted(this);
  Close(false);
}

void Connection::StatementRef::Close(bool forced) {
  if (stmt_) {
    // Call to AssertIOAllowed() cannot go at the beginning of the function
    // because Close() is called unconditionally from destructor to clean
    // connection_. And if this is inactive statement this won't cause any
    // disk access and destructor most probably will be called on thread
    // not allowing disk access.
    // TODO(paivanof@gmail.com): This should move to the beginning
    // of the function. http://crbug.com/136655.
    AssertIOAllowed();
    sqlite3_finalize(stmt_);
    stmt_ = NULL;
  }
  connection_ = NULL;  // The connection may be getting deleted.

  // Forced close is expected to happen from a statement error
  // handler.  In that case maintain the sense of |was_valid_| which
  // previously held for this ref.
  was_valid_ = was_valid_ && forced;
}

Connection::Connection()
    : db_(NULL),
      page_size_(0),
      cache_size_(0),
      exclusive_locking_(false),
      restrict_to_user_(false),
      transaction_nesting_(0),
      needs_rollback_(false),
      in_memory_(false),
      poisoned_(false),
      mmap_disabled_(false),
      mmap_enabled_(false),
      total_changes_at_last_release_(0),
      stats_histogram_(NULL),
      commit_time_histogram_(NULL),
      autocommit_time_histogram_(NULL),
      update_time_histogram_(NULL),
      query_time_histogram_(NULL),
      clock_(new TimeSource()) {
}

Connection::~Connection() {
  Close();
}

void Connection::RecordEvent(Events event, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    UMA_HISTOGRAM_ENUMERATION("Sqlite.Stats", event, EVENT_MAX_VALUE);
  }

  if (stats_histogram_) {
    for (size_t i = 0; i < count; ++i) {
      stats_histogram_->Add(event);
    }
  }
}

void Connection::RecordCommitTime(const base::TimeDelta& delta) {
  RecordUpdateTime(delta);
  UMA_HISTOGRAM_MEDIUM_TIMES("Sqlite.CommitTime", delta);
  if (commit_time_histogram_)
    commit_time_histogram_->AddTime(delta);
}

void Connection::RecordAutoCommitTime(const base::TimeDelta& delta) {
  RecordUpdateTime(delta);
  UMA_HISTOGRAM_MEDIUM_TIMES("Sqlite.AutoCommitTime", delta);
  if (autocommit_time_histogram_)
    autocommit_time_histogram_->AddTime(delta);
}

void Connection::RecordUpdateTime(const base::TimeDelta& delta) {
  RecordQueryTime(delta);
  UMA_HISTOGRAM_MEDIUM_TIMES("Sqlite.UpdateTime", delta);
  if (update_time_histogram_)
    update_time_histogram_->AddTime(delta);
}

void Connection::RecordQueryTime(const base::TimeDelta& delta) {
  UMA_HISTOGRAM_MEDIUM_TIMES("Sqlite.QueryTime", delta);
  if (query_time_histogram_)
    query_time_histogram_->AddTime(delta);
}

void Connection::RecordTimeAndChanges(
    const base::TimeDelta& delta, bool read_only) {
  if (read_only) {
    RecordQueryTime(delta);
  } else {
    const int changes = sqlite3_changes(db_);
    if (sqlite3_get_autocommit(db_)) {
      RecordAutoCommitTime(delta);
      RecordEvent(EVENT_CHANGES_AUTOCOMMIT, changes);
    } else {
      RecordUpdateTime(delta);
      RecordEvent(EVENT_CHANGES, changes);
    }
  }
}

bool Connection::Open(const base::FilePath& path) {
  if (!histogram_tag_.empty()) {
    int64_t size_64 = 0;
    if (base::GetFileSize(path, &size_64)) {
      size_t sample = static_cast<size_t>(size_64 / 1024);
      std::string full_histogram_name = "Sqlite.SizeKB." + histogram_tag_;
      base::HistogramBase* histogram =
          base::Histogram::FactoryGet(
              full_histogram_name, 1, 1000000, 50,
              base::HistogramBase::kUmaTargetedHistogramFlag);
      if (histogram)
        histogram->Add(sample);
      UMA_HISTOGRAM_COUNTS("Sqlite.SizeKB", sample);
    }
  }

  return OpenInternal(AsUTF8ForSQL(path), RETRY_ON_POISON);
}

bool Connection::OpenInMemory() {
  in_memory_ = true;
  return OpenInternal(":memory:", NO_RETRY);
}

bool Connection::OpenTemporary() {
  return OpenInternal("", NO_RETRY);
}

void Connection::CloseInternal(bool forced) {
  // TODO(shess): Calling "PRAGMA journal_mode = DELETE" at this point
  // will delete the -journal file.  For ChromiumOS or other more
  // embedded systems, this is probably not appropriate, whereas on
  // desktop it might make some sense.

  // sqlite3_close() needs all prepared statements to be finalized.

  // Release cached statements.
  statement_cache_.clear();

  // With cached statements released, in-use statements will remain.
  // Closing the database while statements are in use is an API
  // violation, except for forced close (which happens from within a
  // statement's error handler).
  DCHECK(forced || open_statements_.empty());

  // Deactivate any outstanding statements so sqlite3_close() works.
  for (StatementRefSet::iterator i = open_statements_.begin();
       i != open_statements_.end(); ++i)
    (*i)->Close(forced);
  open_statements_.clear();

  if (db_) {
    // Call to AssertIOAllowed() cannot go at the beginning of the function
    // because Close() must be called from destructor to clean
    // statement_cache_, it won't cause any disk access and it most probably
    // will happen on thread not allowing disk access.
    // TODO(paivanof@gmail.com): This should move to the beginning
    // of the function. http://crbug.com/136655.
    AssertIOAllowed();

    // Reseting acquires a lock to ensure no dump is happening on the database
    // at the same time. Unregister takes ownership of provider and it is safe
    // since the db is reset. memory_dump_provider_ could be null if db_ was
    // poisoned.
    if (memory_dump_provider_) {
      memory_dump_provider_->ResetDatabase();
      base::trace_event::MemoryDumpManager::GetInstance()
          ->UnregisterAndDeleteDumpProviderSoon(
              std::move(memory_dump_provider_));
    }

    int rc = sqlite3_close(db_);
    if (rc != SQLITE_OK) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.CloseFailure", rc);
      DLOG(FATAL) << "sqlite3_close failed: " << GetErrorMessage();
    }
  }
  db_ = NULL;
}

void Connection::Close() {
  // If the database was already closed by RazeAndClose(), then no
  // need to close again.  Clear the |poisoned_| bit so that incorrect
  // API calls are caught.
  if (poisoned_) {
    poisoned_ = false;
    return;
  }

  CloseInternal(false);
}

void Connection::Preload() {
  AssertIOAllowed();

  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Cannot preload null db";
    return;
  }

  // Use local settings if provided, otherwise use documented defaults.  The
  // actual results could be fetching via PRAGMA calls.
  const int page_size = page_size_ ? page_size_ : 1024;
  sqlite3_int64 preload_size = page_size * (cache_size_ ? cache_size_ : 2000);
  if (preload_size < 1)
    return;

  sqlite3_file* file = NULL;
  sqlite3_int64 file_size = 0;
  int rc = GetSqlite3FileAndSize(db_, &file, &file_size);
  if (rc != SQLITE_OK)
    return;

  // Don't preload more than the file contains.
  if (preload_size > file_size)
    preload_size = file_size;

  std::unique_ptr<char[]> buf(new char[page_size]);
  for (sqlite3_int64 pos = 0; pos < preload_size; pos += page_size) {
    rc = file->pMethods->xRead(file, buf.get(), page_size, pos);

    // TODO(shess): Consider calling OnSqliteError().
    if (rc != SQLITE_OK)
      return;
  }
}

// SQLite keeps unused pages associated with a connection in a cache.  It asks
// the cache for pages by an id, and if the page is present and the database is
// unchanged, it considers the content of the page valid and doesn't read it
// from disk.  When memory-mapped I/O is enabled, on read SQLite uses page
// structures created from the memory map data before consulting the cache.  On
// write SQLite creates a new in-memory page structure, copies the data from the
// memory map, and later writes it, releasing the updated page back to the
// cache.
//
// This means that in memory-mapped mode, the contents of the cached pages are
// not re-used for reads, but they are re-used for writes if the re-written page
// is still in the cache. The implementation of sqlite3_db_release_memory() as
// of SQLite 3.8.7.4 frees all pages from pcaches associated with the
// connection, so it should free these pages.
//
// Unfortunately, the zero page is also freed.  That page is never accessed
// using memory-mapped I/O, and the cached copy can be re-used after verifying
// the file change counter on disk.  Also, fresh pages from cache receive some
// pager-level initialization before they can be used.  Since the information
// involved will immediately be accessed in various ways, it is unclear if the
// additional overhead is material, or just moving processor cache effects
// around.
//
// TODO(shess): It would be better to release the pages immediately when they
// are no longer needed.  This would basically happen after SQLite commits a
// transaction.  I had implemented a pcache wrapper to do this, but it involved
// layering violations, and it had to be setup before any other sqlite call,
// which was brittle.  Also, for large files it would actually make sense to
// maintain the existing pcache behavior for blocks past the memory-mapped
// segment.  I think drh would accept a reasonable implementation of the overall
// concept for upstreaming to SQLite core.
//
// TODO(shess): Another possibility would be to set the cache size small, which
// would keep the zero page around, plus some pre-initialized pages, and SQLite
// can manage things.  The downside is that updates larger than the cache would
// spill to the journal.  That could be compensated by setting cache_spill to
// false.  The downside then is that it allows open-ended use of memory for
// large transactions.
//
// TODO(shess): The TrimMemory() trick of bouncing the cache size would also
// work.  There could be two prepared statements, one for cache_size=1 one for
// cache_size=goal.
void Connection::ReleaseCacheMemoryIfNeeded(bool implicit_change_performed) {
  // The database could have been closed during a transaction as part of error
  // recovery.
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return;
  }

  // If memory-mapping is not enabled, the page cache helps performance.
  if (!mmap_enabled_)
    return;

  // On caller request, force the change comparison to fail.  Done before the
  // transaction-nesting test so that the signal can carry to transaction
  // commit.
  if (implicit_change_performed)
    --total_changes_at_last_release_;

  // Cached pages may be re-used within the same transaction.
  if (transaction_nesting())
    return;

  // If no changes have been made, skip flushing.  This allows the first page of
  // the database to remain in cache across multiple reads.
  const int total_changes = sqlite3_total_changes(db_);
  if (total_changes == total_changes_at_last_release_)
    return;

  total_changes_at_last_release_ = total_changes;
  sqlite3_db_release_memory(db_);
}

base::FilePath Connection::DbPath() const {
  if (!is_open())
    return base::FilePath();

  const char* path = sqlite3_db_filename(db_, "main");
  const base::StringPiece db_path(path);
#if defined(OS_WIN)
  return base::FilePath(base::UTF8ToWide(db_path));
#elif defined(OS_POSIX)
  return base::FilePath(db_path);
#else
  NOTREACHED();
  return base::FilePath();
#endif
}

// Data is persisted in a file shared between databases in the same directory.
// The "sqlite-diag" file contains a dictionary with the version number, and an
// array of histogram tags for databases which have been dumped.
bool Connection::RegisterIntentToUpload() const {
  static const char* kVersionKey = "version";
  static const char* kDiagnosticDumpsKey = "DiagnosticDumps";
  static int kVersion = 1;

  AssertIOAllowed();

  if (histogram_tag_.empty())
    return false;

  if (!is_open())
    return false;

  if (in_memory_)
    return false;

  const base::FilePath db_path = DbPath();
  if (db_path.empty())
    return false;

  // Put the collection of diagnostic data next to the databases.  In most
  // cases, this is the profile directory, but safe-browsing stores a Cookies
  // file in the directory above the profile directory.
  base::FilePath breadcrumb_path(
      db_path.DirName().Append(FILE_PATH_LITERAL("sqlite-diag")));

  // Lock against multiple updates to the diagnostics file.  This code should
  // seldom be called in the first place, and when called it should seldom be
  // called for multiple databases, and when called for multiple databases there
  // is _probably_ something systemic wrong with the user's system.  So the lock
  // should never be contended, but when it is the database experience is
  // already bad.
  base::AutoLock lock(g_sqlite_init_lock.Get());

  std::unique_ptr<base::Value> root;
  if (!base::PathExists(breadcrumb_path)) {
    std::unique_ptr<base::DictionaryValue> root_dict(
        new base::DictionaryValue());
    root_dict->SetInteger(kVersionKey, kVersion);

    std::unique_ptr<base::ListValue> dumps(new base::ListValue);
    dumps->AppendString(histogram_tag_);
    root_dict->Set(kDiagnosticDumpsKey, std::move(dumps));

    root = std::move(root_dict);
  } else {
    // Failure to read a valid dictionary implies that something is going wrong
    // on the system.
    JSONFileValueDeserializer deserializer(breadcrumb_path);
    std::unique_ptr<base::Value> read_root(
        deserializer.Deserialize(nullptr, nullptr));
    if (!read_root.get())
      return false;
    std::unique_ptr<base::DictionaryValue> root_dict =
        base::DictionaryValue::From(std::move(read_root));
    if (!root_dict)
      return false;

    // Don't upload if the version is missing or newer.
    int version = 0;
    if (!root_dict->GetInteger(kVersionKey, &version) || version > kVersion)
      return false;

    base::ListValue* dumps = nullptr;
    if (!root_dict->GetList(kDiagnosticDumpsKey, &dumps))
      return false;

    const size_t size = dumps->GetSize();
    for (size_t i = 0; i < size; ++i) {
      std::string s;

      // Don't upload if the value isn't a string, or indicates a prior upload.
      if (!dumps->GetString(i, &s) || s == histogram_tag_)
        return false;
    }

    // Record intention to proceed with upload.
    dumps->AppendString(histogram_tag_);
    root = std::move(root_dict);
  }

  const base::FilePath breadcrumb_new =
      breadcrumb_path.AddExtension(FILE_PATH_LITERAL("new"));
  base::DeleteFile(breadcrumb_new, false);

  // No upload if the breadcrumb file cannot be updated.
  // TODO(shess): Consider ImportantFileWriter::WriteFileAtomically() to land
  // the data on disk.  For now, losing the data is not a big problem, so the
  // sync overhead would probably not be worth it.
  JSONFileValueSerializer serializer(breadcrumb_new);
  if (!serializer.Serialize(*root))
    return false;
  if (!base::PathExists(breadcrumb_new))
    return false;
  if (!base::ReplaceFile(breadcrumb_new, breadcrumb_path, nullptr)) {
    base::DeleteFile(breadcrumb_new, false);
    return false;
  }

  return true;
}

std::string Connection::CollectErrorInfo(int error, Statement* stmt) const {
  // Buffer for accumulating debugging info about the error.  Place
  // more-relevant information earlier, in case things overflow the
  // fixed-size reporting buffer.
  std::string debug_info;

  // The error message from the failed operation.
  base::StringAppendF(&debug_info, "db error: %d/%s\n",
                      GetErrorCode(), GetErrorMessage());

  // TODO(shess): |error| and |GetErrorCode()| should always be the same, but
  // reading code does not entirely convince me.  Remove if they turn out to be
  // the same.
  if (error != GetErrorCode())
    base::StringAppendF(&debug_info, "reported error: %d\n", error);

  // System error information.  Interpretation of Windows errors is different
  // from posix.
#if defined(OS_WIN)
  base::StringAppendF(&debug_info, "LastError: %d\n", GetLastErrno());
#elif defined(OS_POSIX)
  base::StringAppendF(&debug_info, "errno: %d\n", GetLastErrno());
#else
  NOTREACHED();  // Add appropriate log info.
#endif

  if (stmt) {
    base::StringAppendF(&debug_info, "statement: %s\n",
                        stmt->GetSQLStatement());
  } else {
    base::StringAppendF(&debug_info, "statement: NULL\n");
  }

  // SQLITE_ERROR often indicates some sort of mismatch between the statement
  // and the schema, possibly due to a failed schema migration.
  if (error == SQLITE_ERROR) {
    const char* kVersionSql = "SELECT value FROM meta WHERE key = 'version'";
    sqlite3_stmt* s;
    int rc = sqlite3_prepare_v2(db_, kVersionSql, -1, &s, nullptr);
    if (rc == SQLITE_OK) {
      rc = sqlite3_step(s);
      if (rc == SQLITE_ROW) {
        base::StringAppendF(&debug_info, "version: %d\n",
                            sqlite3_column_int(s, 0));
      } else if (rc == SQLITE_DONE) {
        debug_info += "version: none\n";
      } else {
        base::StringAppendF(&debug_info, "version: error %d\n", rc);
      }
      sqlite3_finalize(s);
    } else {
      base::StringAppendF(&debug_info, "version: prepare error %d\n", rc);
    }

    debug_info += "schema:\n";

    // sqlite_master has columns:
    //   type - "index" or "table".
    //   name - name of created element.
    //   tbl_name - name of element, or target table in case of index.
    //   rootpage - root page of the element in database file.
    //   sql - SQL to create the element.
    // In general, the |sql| column is sufficient to derive the other columns.
    // |rootpage| is not interesting for debugging, without the contents of the
    // database.  The COALESCE is because certain automatic elements will have a
    // |name| but no |sql|,
    const char* kSchemaSql = "SELECT COALESCE(sql, name) FROM sqlite_master";
    rc = sqlite3_prepare_v2(db_, kSchemaSql, -1, &s, nullptr);
    if (rc == SQLITE_OK) {
      while ((rc = sqlite3_step(s)) == SQLITE_ROW) {
        base::StringAppendF(&debug_info, "%s\n", sqlite3_column_text(s, 0));
      }
      if (rc != SQLITE_DONE)
        base::StringAppendF(&debug_info, "error %d\n", rc);
      sqlite3_finalize(s);
    } else {
      base::StringAppendF(&debug_info, "prepare error %d\n", rc);
    }
  }

  return debug_info;
}

// TODO(shess): Since this is only called in an error situation, it might be
// prudent to rewrite in terms of SQLite API calls, and mark the function const.
std::string Connection::CollectCorruptionInfo() {
  AssertIOAllowed();

  // If the file cannot be accessed it is unlikely that an integrity check will
  // turn up actionable information.
  const base::FilePath db_path = DbPath();
  int64_t db_size = -1;
  if (!base::GetFileSize(db_path, &db_size) || db_size < 0)
    return std::string();

  // Buffer for accumulating debugging info about the error.  Place
  // more-relevant information earlier, in case things overflow the
  // fixed-size reporting buffer.
  std::string debug_info;
  base::StringAppendF(&debug_info, "SQLITE_CORRUPT, db size %" PRId64 "\n",
                      db_size);

  // Only check files up to 8M to keep things from blocking too long.
  const int64_t kMaxIntegrityCheckSize = 8192 * 1024;
  if (db_size > kMaxIntegrityCheckSize) {
    debug_info += "integrity_check skipped due to size\n";
  } else {
    std::vector<std::string> messages;

    // TODO(shess): FullIntegrityCheck() splits into a vector while this joins
    // into a string.  Probably should be refactored.
    const base::TimeTicks before = base::TimeTicks::Now();
    FullIntegrityCheck(&messages);
    base::StringAppendF(
        &debug_info,
        "integrity_check %" PRId64 " ms, %" PRIuS " records:\n",
        (base::TimeTicks::Now() - before).InMilliseconds(),
        messages.size());

    // SQLite returns up to 100 messages by default, trim deeper to
    // keep close to the 2000-character size limit for dumping.
    const size_t kMaxMessages = 20;
    for (size_t i = 0; i < kMaxMessages && i < messages.size(); ++i) {
      base::StringAppendF(&debug_info, "%s\n", messages[i].c_str());
    }
  }

  return debug_info;
}

size_t Connection::GetAppropriateMmapSize() {
  AssertIOAllowed();

#if defined(OS_IOS) && defined(USE_SYSTEM_SQLITE)
  if (!base::ios::IsRunningOnIOS10OrLater()) {
    // iOS SQLite does not support memory mapping.
    return 0;
  }
#endif

  // How much to map if no errors are found.  50MB encompasses the 99th
  // percentile of Chrome databases in the wild, so this should be good.
  const size_t kMmapEverything = 256 * 1024 * 1024;

  // If the database doesn't have a place to track progress, assume the best.
  // This will happen when new databases are created, or if a database doesn't
  // use a meta table.  sql::MetaTable::Init() will preload kMmapSuccess.
  // TODO(shess): Databases not using meta include:
  //   DOMStorageDatabase (localstorage)
  //   ActivityDatabase (extensions activity log)
  //   PredictorDatabase (prefetch and autocomplete predictor data)
  //   SyncDirectory (sync metadata storage)
  // For now, these all have mmap disabled to allow other databases to get the
  // default-enable path.  sqlite-diag could be an alternative for all but
  // DOMStorageDatabase, which creates many small databases.
  // http://crbug.com/537742
  if (!MetaTable::DoesTableExist(this)) {
    RecordOneEvent(EVENT_MMAP_META_MISSING);
    return kMmapEverything;
  }

  int64_t mmap_ofs = 0;
  if (!MetaTable::GetMmapStatus(this, &mmap_ofs)) {
    RecordOneEvent(EVENT_MMAP_META_FAILURE_READ);
    return 0;
  }

  // Database read failed in the past, don't memory map.
  if (mmap_ofs == MetaTable::kMmapFailure) {
    RecordOneEvent(EVENT_MMAP_FAILED);
    return 0;
  } else if (mmap_ofs != MetaTable::kMmapSuccess) {
    // Continue reading from previous offset.
    DCHECK_GE(mmap_ofs, 0);

    // TODO(shess): Could this reading code be shared with Preload()?  It would
    // require locking twice (this code wouldn't be able to access |db_size| so
    // the helper would have to return amount read).

    // Read more of the database looking for errors.  The VFS interface is used
    // to assure that the reads are valid for SQLite.  |g_reads_allowed| is used
    // to limit checking to 20MB per run of Chromium.
    sqlite3_file* file = NULL;
    sqlite3_int64 db_size = 0;
    if (SQLITE_OK != GetSqlite3FileAndSize(db_, &file, &db_size)) {
      RecordOneEvent(EVENT_MMAP_VFS_FAILURE);
      return 0;
    }

    // Read the data left, or |g_reads_allowed|, whichever is smaller.
    // |g_reads_allowed| limits the total amount of I/O to spend verifying data
    // in a single Chromium run.
    sqlite3_int64 amount = db_size - mmap_ofs;
    if (amount < 0)
      amount = 0;
    if (amount > 0) {
      base::AutoLock lock(g_sqlite_init_lock.Get());
      static sqlite3_int64 g_reads_allowed = 20 * 1024 * 1024;
      if (g_reads_allowed < amount)
        amount = g_reads_allowed;
      g_reads_allowed -= amount;
    }

    // |amount| can be <= 0 if |g_reads_allowed| ran out of quota, or if the
    // database was truncated after a previous pass.
    if (amount <= 0 && mmap_ofs < db_size) {
      DCHECK_EQ(0, amount);
      RecordOneEvent(EVENT_MMAP_SUCCESS_NO_PROGRESS);
    } else {
      static const int kPageSize = 4096;
      char buf[kPageSize];
      while (amount > 0) {
        int rc = file->pMethods->xRead(file, buf, sizeof(buf), mmap_ofs);
        if (rc == SQLITE_OK) {
          mmap_ofs += sizeof(buf);
          amount -= sizeof(buf);
        } else if (rc == SQLITE_IOERR_SHORT_READ) {
          // Reached EOF for a database with page size < |kPageSize|.
          mmap_ofs = db_size;
          break;
        } else {
          // TODO(shess): Consider calling OnSqliteError().
          mmap_ofs = MetaTable::kMmapFailure;
          break;
        }
      }

      // Log these events after update to distinguish meta update failure.
      Events event;
      if (mmap_ofs >= db_size) {
        mmap_ofs = MetaTable::kMmapSuccess;
        event = EVENT_MMAP_SUCCESS_NEW;
      } else if (mmap_ofs > 0) {
        event = EVENT_MMAP_SUCCESS_PARTIAL;
      } else {
        DCHECK_EQ(MetaTable::kMmapFailure, mmap_ofs);
        event = EVENT_MMAP_FAILED_NEW;
      }

      if (!MetaTable::SetMmapStatus(this, mmap_ofs)) {
        RecordOneEvent(EVENT_MMAP_META_FAILURE_UPDATE);
        return 0;
      }

      RecordOneEvent(event);
    }
  }

  if (mmap_ofs == MetaTable::kMmapFailure)
    return 0;
  if (mmap_ofs == MetaTable::kMmapSuccess)
    return kMmapEverything;
  return mmap_ofs;
}

void Connection::TrimMemory(bool aggressively) {
  if (!db_)
    return;

  // TODO(shess): investigate using sqlite3_db_release_memory() when possible.
  int original_cache_size;
  {
    Statement sql_get_original(GetUniqueStatement("PRAGMA cache_size"));
    if (!sql_get_original.Step()) {
      DLOG(WARNING) << "Could not get cache size " << GetErrorMessage();
      return;
    }
    original_cache_size = sql_get_original.ColumnInt(0);
  }
  int shrink_cache_size = aggressively ? 1 : (original_cache_size / 2);

  // Force sqlite to try to reduce page cache usage.
  const std::string sql_shrink =
      base::StringPrintf("PRAGMA cache_size=%d", shrink_cache_size);
  if (!Execute(sql_shrink.c_str()))
    DLOG(WARNING) << "Could not shrink cache size: " << GetErrorMessage();

  // Restore cache size.
  const std::string sql_restore =
      base::StringPrintf("PRAGMA cache_size=%d", original_cache_size);
  if (!Execute(sql_restore.c_str()))
    DLOG(WARNING) << "Could not restore cache size: " << GetErrorMessage();
}

// Create an in-memory database with the existing database's page
// size, then backup that database over the existing database.
bool Connection::Raze() {
  AssertIOAllowed();

  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Cannot raze null db";
    return false;
  }

  if (transaction_nesting_ > 0) {
    DLOG(FATAL) << "Cannot raze within a transaction";
    return false;
  }

  sql::Connection null_db;
  if (!null_db.OpenInMemory()) {
    DLOG(FATAL) << "Unable to open in-memory database.";
    return false;
  }

  if (page_size_) {
    // Enforce SQLite restrictions on |page_size_|.
    DCHECK(!(page_size_ & (page_size_ - 1)))
        << " page_size_ " << page_size_ << " is not a power of two.";
    const int kSqliteMaxPageSize = 32768;  // from sqliteLimit.h
    DCHECK_LE(page_size_, kSqliteMaxPageSize);
    const std::string sql =
        base::StringPrintf("PRAGMA page_size=%d", page_size_);
    if (!null_db.Execute(sql.c_str()))
      return false;
  }

#if defined(OS_ANDROID)
  // Android compiles with SQLITE_DEFAULT_AUTOVACUUM.  Unfortunately,
  // in-memory databases do not respect this define.
  // TODO(shess): Figure out a way to set this without using platform
  // specific code.  AFAICT from sqlite3.c, the only way to do it
  // would be to create an actual filesystem database, which is
  // unfortunate.
  if (!null_db.Execute("PRAGMA auto_vacuum = 1"))
    return false;
#endif

  // The page size doesn't take effect until a database has pages, and
  // at this point the null database has none.  Changing the schema
  // version will create the first page.  This will not affect the
  // schema version in the resulting database, as SQLite's backup
  // implementation propagates the schema version from the original
  // connection to the new version of the database, incremented by one
  // so that other readers see the schema change and act accordingly.
  if (!null_db.Execute("PRAGMA schema_version = 1"))
    return false;

  // SQLite tracks the expected number of database pages in the first
  // page, and if it does not match the total retrieved from a
  // filesystem call, treats the database as corrupt.  This situation
  // breaks almost all SQLite calls.  "PRAGMA writable_schema" can be
  // used to hint to SQLite to soldier on in that case, specifically
  // for purposes of recovery.  [See SQLITE_CORRUPT_BKPT case in
  // sqlite3.c lockBtree().]
  // TODO(shess): With this, "PRAGMA auto_vacuum" and "PRAGMA
  // page_size" can be used to query such a database.
  ScopedWritableSchema writable_schema(db_);

  const char* kMain = "main";
  int rc = BackupDatabase(null_db.db_, db_, kMain);
  UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.RazeDatabase",rc);

  // The destination database was locked.
  if (rc == SQLITE_BUSY) {
    return false;
  }

  // SQLITE_NOTADB can happen if page 1 of db_ exists, but is not
  // formatted correctly.  SQLITE_IOERR_SHORT_READ can happen if db_
  // isn't even big enough for one page.  Either way, reach in and
  // truncate it before trying again.
  // TODO(shess): Maybe it would be worthwhile to just truncate from
  // the get-go?
  if (rc == SQLITE_NOTADB || rc == SQLITE_IOERR_SHORT_READ) {
    sqlite3_file* file = NULL;
    rc = GetSqlite3File(db_, &file);
    if (rc != SQLITE_OK) {
      DLOG(FATAL) << "Failure getting file handle.";
      return false;
    }

    rc = file->pMethods->xTruncate(file, 0);
    if (rc != SQLITE_OK) {
      UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.RazeDatabaseTruncate",rc);
      DLOG(FATAL) << "Failed to truncate file.";
      return false;
    }

    rc = BackupDatabase(null_db.db_, db_, kMain);
    UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.RazeDatabase2",rc);

    if (rc != SQLITE_DONE) {
      DLOG(FATAL) << "Failed retrying Raze().";
    }
  }

  // The entire database should have been backed up.
  if (rc != SQLITE_DONE) {
    // TODO(shess): Figure out which other cases can happen.
    DLOG(FATAL) << "Unable to copy entire null database.";
    return false;
  }

  return true;
}

bool Connection::RazeWithTimout(base::TimeDelta timeout) {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Cannot raze null db";
    return false;
  }

  ScopedBusyTimeout busy_timeout(db_);
  busy_timeout.SetTimeout(timeout);
  return Raze();
}

bool Connection::RazeAndClose() {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Cannot raze null db";
    return false;
  }

  // Raze() cannot run in a transaction.
  RollbackAllTransactions();

  bool result = Raze();

  CloseInternal(true);

  // Mark the database so that future API calls fail appropriately,
  // but don't DCHECK (because after calling this function they are
  // expected to fail).
  poisoned_ = true;

  return result;
}

void Connection::Poison() {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Cannot poison null db";
    return;
  }

  RollbackAllTransactions();
  CloseInternal(true);

  // Mark the database so that future API calls fail appropriately,
  // but don't DCHECK (because after calling this function they are
  // expected to fail).
  poisoned_ = true;
}

// TODO(shess): To the extent possible, figure out the optimal
// ordering for these deletes which will prevent other connections
// from seeing odd behavior.  For instance, it may be necessary to
// manually lock the main database file in a SQLite-compatible fashion
// (to prevent other processes from opening it), then delete the
// journal files, then delete the main database file.  Another option
// might be to lock the main database file and poison the header with
// junk to prevent other processes from opening it successfully (like
// Gears "SQLite poison 3" trick).
//
// static
bool Connection::Delete(const base::FilePath& path) {
  base::ThreadRestrictions::AssertIOAllowed();

  base::FilePath journal_path(path.value() + FILE_PATH_LITERAL("-journal"));
  base::FilePath wal_path(path.value() + FILE_PATH_LITERAL("-wal"));

  std::string journal_str = AsUTF8ForSQL(journal_path);
  std::string wal_str = AsUTF8ForSQL(wal_path);
  std::string path_str = AsUTF8ForSQL(path);

  // Make sure sqlite3_initialize() is called before anything else.
  InitializeSqlite();

  sqlite3_vfs* vfs = sqlite3_vfs_find(NULL);
  CHECK(vfs);
  CHECK(vfs->xDelete);
  CHECK(vfs->xAccess);

  // We only work with unix, win32 and mojo filesystems. If you're trying to
  // use this code with any other VFS, you're not in a good place.
  CHECK(strncmp(vfs->zName, "unix", 4) == 0 ||
        strncmp(vfs->zName, "win32", 5) == 0 ||
        strcmp(vfs->zName, "mojo") == 0);

  vfs->xDelete(vfs, journal_str.c_str(), 0);
  vfs->xDelete(vfs, wal_str.c_str(), 0);
  vfs->xDelete(vfs, path_str.c_str(), 0);

  int journal_exists = 0;
  vfs->xAccess(vfs, journal_str.c_str(), SQLITE_ACCESS_EXISTS,
               &journal_exists);

  int wal_exists = 0;
  vfs->xAccess(vfs, wal_str.c_str(), SQLITE_ACCESS_EXISTS,
               &wal_exists);

  int path_exists = 0;
  vfs->xAccess(vfs, path_str.c_str(), SQLITE_ACCESS_EXISTS,
               &path_exists);

  return !journal_exists && !wal_exists && !path_exists;
}

bool Connection::BeginTransaction() {
  if (needs_rollback_) {
    DCHECK_GT(transaction_nesting_, 0);

    // When we're going to rollback, fail on this begin and don't actually
    // mark us as entering the nested transaction.
    return false;
  }

  bool success = true;
  if (!transaction_nesting_) {
    needs_rollback_ = false;

    Statement begin(GetCachedStatement(SQL_FROM_HERE, "BEGIN TRANSACTION"));
    RecordOneEvent(EVENT_BEGIN);
    if (!begin.Run())
      return false;
  }
  transaction_nesting_++;
  return success;
}

void Connection::RollbackTransaction() {
  if (!transaction_nesting_) {
    DLOG_IF(FATAL, !poisoned_) << "Rolling back a nonexistent transaction";
    return;
  }

  transaction_nesting_--;

  if (transaction_nesting_ > 0) {
    // Mark the outermost transaction as needing rollback.
    needs_rollback_ = true;
    return;
  }

  DoRollback();
}

bool Connection::CommitTransaction() {
  if (!transaction_nesting_) {
    DLOG_IF(FATAL, !poisoned_) << "Committing a nonexistent transaction";
    return false;
  }
  transaction_nesting_--;

  if (transaction_nesting_ > 0) {
    // Mark any nested transactions as failing after we've already got one.
    return !needs_rollback_;
  }

  if (needs_rollback_) {
    DoRollback();
    return false;
  }

  Statement commit(GetCachedStatement(SQL_FROM_HERE, "COMMIT"));

  // Collect the commit time manually, sql::Statement would register it as query
  // time only.
  const base::TimeTicks before = Now();
  bool ret = commit.RunWithoutTimers();
  const base::TimeDelta delta = Now() - before;

  RecordCommitTime(delta);
  RecordOneEvent(EVENT_COMMIT);

  // Release dirty cache pages after the transaction closes.
  ReleaseCacheMemoryIfNeeded(false);

  return ret;
}

void Connection::RollbackAllTransactions() {
  if (transaction_nesting_ > 0) {
    transaction_nesting_ = 0;
    DoRollback();
  }
}

bool Connection::AttachDatabase(const base::FilePath& other_db_path,
                                const char* attachment_point) {
  DCHECK(ValidAttachmentPoint(attachment_point));

  Statement s(GetUniqueStatement("ATTACH DATABASE ? AS ?"));
#if OS_WIN
  s.BindString16(0, other_db_path.value());
#else
  s.BindString(0, other_db_path.value());
#endif
  s.BindString(1, attachment_point);
  return s.Run();
}

bool Connection::DetachDatabase(const char* attachment_point) {
  DCHECK(ValidAttachmentPoint(attachment_point));

  Statement s(GetUniqueStatement("DETACH DATABASE ?"));
  s.BindString(0, attachment_point);
  return s.Run();
}

// TODO(shess): Consider changing this to execute exactly one statement.  If a
// caller wishes to execute multiple statements, that should be explicit, and
// perhaps tucked into an explicit transaction with rollback in case of error.
int Connection::ExecuteAndReturnErrorCode(const char* sql) {
  AssertIOAllowed();
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return SQLITE_ERROR;
  }
  DCHECK(sql);

  RecordOneEvent(EVENT_EXECUTE);
  int rc = SQLITE_OK;
  while ((rc == SQLITE_OK) && *sql) {
    sqlite3_stmt *stmt = NULL;
    const char *leftover_sql;

    const base::TimeTicks before = Now();
    rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, &leftover_sql);
    sql = leftover_sql;

    // Stop if an error is encountered.
    if (rc != SQLITE_OK)
      break;

    // This happens if |sql| originally only contained comments or whitespace.
    // TODO(shess): Audit to see if this can become a DCHECK().  Having
    // extraneous comments and whitespace in the SQL statements increases
    // runtime cost and can easily be shifted out to the C++ layer.
    if (!stmt)
      continue;

    // Save for use after statement is finalized.
    const bool read_only = !!sqlite3_stmt_readonly(stmt);

    RecordOneEvent(Connection::EVENT_STATEMENT_RUN);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
      // TODO(shess): Audit to see if this can become a DCHECK.  I think PRAGMA
      // is the only legitimate case for this.
      RecordOneEvent(Connection::EVENT_STATEMENT_ROWS);
    }

    // sqlite3_finalize() returns SQLITE_OK if the most recent sqlite3_step()
    // returned SQLITE_DONE or SQLITE_ROW, otherwise the error code.
    rc = sqlite3_finalize(stmt);
    if (rc == SQLITE_OK)
      RecordOneEvent(Connection::EVENT_STATEMENT_SUCCESS);

    // sqlite3_exec() does this, presumably to avoid spinning the parser for
    // trailing whitespace.
    // TODO(shess): Audit to see if this can become a DCHECK.
    while (base::IsAsciiWhitespace(*sql)) {
      sql++;
    }

    const base::TimeDelta delta = Now() - before;
    RecordTimeAndChanges(delta, read_only);
  }

  // Most calls to Execute() modify the database.  The main exceptions would be
  // calls such as CREATE TABLE IF NOT EXISTS which could modify the database
  // but sometimes don't.
  ReleaseCacheMemoryIfNeeded(true);

  return rc;
}

bool Connection::Execute(const char* sql) {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return false;
  }

  int error = ExecuteAndReturnErrorCode(sql);
  if (error != SQLITE_OK)
    error = OnSqliteError(error, NULL, sql);

  // This needs to be a FATAL log because the error case of arriving here is
  // that there's a malformed SQL statement. This can arise in development if
  // a change alters the schema but not all queries adjust.  This can happen
  // in production if the schema is corrupted.
  if (error == SQLITE_ERROR)
    DLOG(FATAL) << "SQL Error in " << sql << ", " << GetErrorMessage();
  return error == SQLITE_OK;
}

bool Connection::ExecuteWithTimeout(const char* sql, base::TimeDelta timeout) {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return false;
  }

  ScopedBusyTimeout busy_timeout(db_);
  busy_timeout.SetTimeout(timeout);
  return Execute(sql);
}

bool Connection::HasCachedStatement(const StatementID& id) const {
  return statement_cache_.find(id) != statement_cache_.end();
}

scoped_refptr<Connection::StatementRef> Connection::GetCachedStatement(
    const StatementID& id,
    const char* sql) {
  CachedStatementMap::iterator i = statement_cache_.find(id);
  if (i != statement_cache_.end()) {
    // Statement is in the cache. It should still be active (we're the only
    // one invalidating cached statements, and we'll remove it from the cache
    // if we do that. Make sure we reset it before giving out the cached one in
    // case it still has some stuff bound.
    DCHECK(i->second->is_valid());
    sqlite3_reset(i->second->stmt());
    return i->second;
  }

  scoped_refptr<StatementRef> statement = GetUniqueStatement(sql);
  if (statement->is_valid())
    statement_cache_[id] = statement;  // Only cache valid statements.
  return statement;
}

scoped_refptr<Connection::StatementRef> Connection::GetUniqueStatement(
    const char* sql) {
  return GetStatementImpl(this, sql);
}

scoped_refptr<Connection::StatementRef> Connection::GetStatementImpl(
    sql::Connection* tracking_db, const char* sql) const {
  AssertIOAllowed();
  DCHECK(sql);
  DCHECK(!tracking_db || const_cast<Connection*>(tracking_db)==this);

  // Return inactive statement.
  if (!db_)
    return new StatementRef(NULL, NULL, poisoned_);

  sqlite3_stmt* stmt = NULL;
  int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    // This is evidence of a syntax error in the incoming SQL.
    if (rc == SQLITE_ERROR)
      DLOG(FATAL) << "SQL compile error " << GetErrorMessage();

    // It could also be database corruption.
    OnSqliteError(rc, NULL, sql);
    return new StatementRef(NULL, NULL, false);
  }
  return new StatementRef(tracking_db, stmt, true);
}

scoped_refptr<Connection::StatementRef> Connection::GetUntrackedStatement(
    const char* sql) const {
  return GetStatementImpl(NULL, sql);
}

std::string Connection::GetSchema() const {
  // The ORDER BY should not be necessary, but relying on organic
  // order for something like this is questionable.
  const char* kSql =
      "SELECT type, name, tbl_name, sql "
      "FROM sqlite_master ORDER BY 1, 2, 3, 4";
  Statement statement(GetUntrackedStatement(kSql));

  std::string schema;
  while (statement.Step()) {
    schema += statement.ColumnString(0);
    schema += '|';
    schema += statement.ColumnString(1);
    schema += '|';
    schema += statement.ColumnString(2);
    schema += '|';
    schema += statement.ColumnString(3);
    schema += '\n';
  }

  return schema;
}

bool Connection::IsSQLValid(const char* sql) {
  AssertIOAllowed();
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return false;
  }

  sqlite3_stmt* stmt = NULL;
  if (sqlite3_prepare_v2(db_, sql, -1, &stmt, NULL) != SQLITE_OK)
    return false;

  sqlite3_finalize(stmt);
  return true;
}

bool Connection::DoesTableExist(const char* table_name) const {
  return DoesTableOrIndexExist(table_name, "table");
}

bool Connection::DoesIndexExist(const char* index_name) const {
  return DoesTableOrIndexExist(index_name, "index");
}

bool Connection::DoesTableOrIndexExist(
    const char* name, const char* type) const {
  const char* kSql =
      "SELECT name FROM sqlite_master WHERE type=? AND name=? COLLATE NOCASE";
  Statement statement(GetUntrackedStatement(kSql));

  // This can happen if the database is corrupt and the error is a test
  // expectation.
  if (!statement.is_valid())
    return false;

  statement.BindString(0, type);
  statement.BindString(1, name);

  return statement.Step();  // Table exists if any row was returned.
}

bool Connection::DoesColumnExist(const char* table_name,
                                 const char* column_name) const {
  std::string sql("PRAGMA TABLE_INFO(");
  sql.append(table_name);
  sql.append(")");

  Statement statement(GetUntrackedStatement(sql.c_str()));

  // This can happen if the database is corrupt and the error is a test
  // expectation.
  if (!statement.is_valid())
    return false;

  while (statement.Step()) {
    if (base::EqualsCaseInsensitiveASCII(statement.ColumnString(1),
                                         column_name))
      return true;
  }
  return false;
}

int64_t Connection::GetLastInsertRowId() const {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return 0;
  }
  return sqlite3_last_insert_rowid(db_);
}

int Connection::GetLastChangeCount() const {
  if (!db_) {
    DLOG_IF(FATAL, !poisoned_) << "Illegal use of connection without a db";
    return 0;
  }
  return sqlite3_changes(db_);
}

int Connection::GetErrorCode() const {
  if (!db_)
    return SQLITE_ERROR;
  return sqlite3_errcode(db_);
}

int Connection::GetLastErrno() const {
  if (!db_)
    return -1;

  int err = 0;
  if (SQLITE_OK != sqlite3_file_control(db_, NULL, SQLITE_LAST_ERRNO, &err))
    return -2;

  return err;
}

const char* Connection::GetErrorMessage() const {
  if (!db_)
    return "sql::Connection has no connection.";
  return sqlite3_errmsg(db_);
}

bool Connection::OpenInternal(const std::string& file_name,
                              Connection::Retry retry_flag) {
  AssertIOAllowed();

  if (db_) {
    DLOG(FATAL) << "sql::Connection is already open.";
    return false;
  }

  // Make sure sqlite3_initialize() is called before anything else.
  InitializeSqlite();

  // Setup the stats histograms immediately rather than allocating lazily.
  // Connections which won't exercise all of these probably shouldn't exist.
  if (!histogram_tag_.empty()) {
    stats_histogram_ =
        base::LinearHistogram::FactoryGet(
            "Sqlite.Stats." + histogram_tag_,
            1, EVENT_MAX_VALUE, EVENT_MAX_VALUE + 1,
            base::HistogramBase::kUmaTargetedHistogramFlag);

    // The timer setup matches UMA_HISTOGRAM_MEDIUM_TIMES().  3 minutes is an
    // unreasonable time for any single operation, so there is not much value to
    // knowing if it was 3 minutes or 5 minutes.  In reality at that point
    // things are entirely busted.
    commit_time_histogram_ =
        GetMediumTimeHistogram("Sqlite.CommitTime." + histogram_tag_);

    autocommit_time_histogram_ =
        GetMediumTimeHistogram("Sqlite.AutoCommitTime." + histogram_tag_);

    update_time_histogram_ =
        GetMediumTimeHistogram("Sqlite.UpdateTime." + histogram_tag_);

    query_time_histogram_ =
        GetMediumTimeHistogram("Sqlite.QueryTime." + histogram_tag_);
  }

  // If |poisoned_| is set, it means an error handler called
  // RazeAndClose().  Until regular Close() is called, the caller
  // should be treating the database as open, but is_open() currently
  // only considers the sqlite3 handle's state.
  // TODO(shess): Revise is_open() to consider poisoned_, and review
  // to see if any non-testing code even depends on it.
  DLOG_IF(FATAL, poisoned_) << "sql::Connection is already open.";
  poisoned_ = false;

  int err = sqlite3_open(file_name.c_str(), &db_);
  if (err != SQLITE_OK) {
    // Extended error codes cannot be enabled until a handle is
    // available, fetch manually.
    err = sqlite3_extended_errcode(db_);

    // Histogram failures specific to initial open for debugging
    // purposes.
    UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.OpenFailure", err);

    OnSqliteError(err, NULL, "-- sqlite3_open()");
    bool was_poisoned = poisoned_;
    Close();

    if (was_poisoned && retry_flag == RETRY_ON_POISON)
      return OpenInternal(file_name, NO_RETRY);
    return false;
  }

  // TODO(shess): OS_WIN support?
#if defined(OS_POSIX)
  if (restrict_to_user_) {
    DCHECK_NE(file_name, std::string(":memory"));
    base::FilePath file_path(file_name);
    int mode = 0;
    // TODO(shess): Arguably, failure to retrieve and change
    // permissions should be fatal if the file exists.
    if (base::GetPosixFilePermissions(file_path, &mode)) {
      mode &= base::FILE_PERMISSION_USER_MASK;
      base::SetPosixFilePermissions(file_path, mode);

      // SQLite sets the permissions on these files from the main
      // database on create.  Set them here in case they already exist
      // at this point.  Failure to set these permissions should not
      // be fatal unless the file doesn't exist.
      base::FilePath journal_path(file_name + FILE_PATH_LITERAL("-journal"));
      base::FilePath wal_path(file_name + FILE_PATH_LITERAL("-wal"));
      base::SetPosixFilePermissions(journal_path, mode);
      base::SetPosixFilePermissions(wal_path, mode);
    }
  }
#endif  // defined(OS_POSIX)

  // SQLite uses a lookaside buffer to improve performance of small mallocs.
  // Chromium already depends on small mallocs being efficient, so we disable
  // this to avoid the extra memory overhead.
  // This must be called immediatly after opening the database before any SQL
  // statements are run.
  sqlite3_db_config(db_, SQLITE_DBCONFIG_LOOKASIDE, NULL, 0, 0);

  // Enable extended result codes to provide more color on I/O errors.
  // Not having extended result codes is not a fatal problem, as
  // Chromium code does not attempt to handle I/O errors anyhow.  The
  // current implementation always returns SQLITE_OK, the DCHECK is to
  // quickly notify someone if SQLite changes.
  err = sqlite3_extended_result_codes(db_, 1);
  DCHECK_EQ(err, SQLITE_OK) << "Could not enable extended result codes";

  // sqlite3_open() does not actually read the database file (unless a hot
  // journal is found).  Successfully executing this pragma on an existing
  // database requires a valid header on page 1.  ExecuteAndReturnErrorCode() to
  // get the error code before error callback (potentially) overwrites.
  // TODO(shess): For now, just probing to see what the lay of the
  // land is.  If it's mostly SQLITE_NOTADB, then the database should
  // be razed.
  err = ExecuteAndReturnErrorCode("PRAGMA auto_vacuum");
  if (err != SQLITE_OK) {
    UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.OpenProbeFailure", err);
    OnSqliteError(err, nullptr, "PRAGMA auto_vacuum");

    // Retry or bail out if the error handler poisoned the handle.
    // TODO(shess): Move this handling to one place (see also sqlite3_open and
    // secure_delete).  Possibly a wrapper function?
    if (poisoned_) {
      Close();
      if (retry_flag == RETRY_ON_POISON)
        return OpenInternal(file_name, NO_RETRY);
      return false;
    }
  }

#if defined(OS_IOS) && defined(USE_SYSTEM_SQLITE)
  // The version of SQLite shipped with iOS doesn't enable ICU, which includes
  // REGEXP support. Add it in dynamically.
  err = sqlite3IcuInit(db_);
  DCHECK_EQ(err, SQLITE_OK) << "Could not enable ICU support";
#endif  // OS_IOS && USE_SYSTEM_SQLITE

  // If indicated, lock up the database before doing anything else, so
  // that the following code doesn't have to deal with locking.
  // TODO(shess): This code is brittle.  Find the cases where code
  // doesn't request |exclusive_locking_| and audit that it does the
  // right thing with SQLITE_BUSY, and that it doesn't make
  // assumptions about who might change things in the database.
  // http://crbug.com/56559
  if (exclusive_locking_) {
    // TODO(shess): This should probably be a failure.  Code which
    // requests exclusive locking but doesn't get it is almost certain
    // to be ill-tested.
    ignore_result(Execute("PRAGMA locking_mode=EXCLUSIVE"));
  }

  // http://www.sqlite.org/pragma.html#pragma_journal_mode
  // DELETE (default) - delete -journal file to commit.
  // TRUNCATE - truncate -journal file to commit.
  // PERSIST - zero out header of -journal file to commit.
  // TRUNCATE should be faster than DELETE because it won't need directory
  // changes for each transaction.  PERSIST may break the spirit of using
  // secure_delete.
  ignore_result(Execute("PRAGMA journal_mode = TRUNCATE"));

  const base::TimeDelta kBusyTimeout =
    base::TimeDelta::FromSeconds(kBusyTimeoutSeconds);

  if (page_size_ != 0) {
    // Enforce SQLite restrictions on |page_size_|.
    DCHECK(!(page_size_ & (page_size_ - 1)))
        << " page_size_ " << page_size_ << " is not a power of two.";
    const int kSqliteMaxPageSize = 32768;  // from sqliteLimit.h
    DCHECK_LE(page_size_, kSqliteMaxPageSize);
    const std::string sql =
        base::StringPrintf("PRAGMA page_size=%d", page_size_);
    ignore_result(ExecuteWithTimeout(sql.c_str(), kBusyTimeout));
  }

  if (cache_size_ != 0) {
    const std::string sql =
        base::StringPrintf("PRAGMA cache_size=%d", cache_size_);
    ignore_result(ExecuteWithTimeout(sql.c_str(), kBusyTimeout));
  }

  if (!ExecuteWithTimeout("PRAGMA secure_delete=ON", kBusyTimeout)) {
    bool was_poisoned = poisoned_;
    Close();
    if (was_poisoned && retry_flag == RETRY_ON_POISON)
      return OpenInternal(file_name, NO_RETRY);
    return false;
  }

  // Set a reasonable chunk size for larger files.  This reduces churn from
  // remapping memory on size changes.  It also reduces filesystem
  // fragmentation.
  // TODO(shess): It may make sense to have this be hinted by the client.
  // Database sizes seem to be bimodal, some clients have consistently small
  // databases (<20k) while other clients have a broad distribution of sizes
  // (hundreds of kilobytes to many megabytes).
  sqlite3_file* file = NULL;
  sqlite3_int64 db_size = 0;
  int rc = GetSqlite3FileAndSize(db_, &file, &db_size);
  if (rc == SQLITE_OK && db_size > 16 * 1024) {
    int chunk_size = 4 * 1024;
    if (db_size > 128 * 1024)
      chunk_size = 32 * 1024;
    sqlite3_file_control(db_, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunk_size);
  }

  // Enable memory-mapped access.  The explicit-disable case is because SQLite
  // can be built to default-enable mmap.  GetAppropriateMmapSize() calculates a
  // safe range to memory-map based on past regular I/O.  This value will be
  // capped by SQLITE_MAX_MMAP_SIZE, which could be different between 32-bit and
  // 64-bit platforms.
  size_t mmap_size = mmap_disabled_ ? 0 : GetAppropriateMmapSize();
  std::string mmap_sql =
      base::StringPrintf("PRAGMA mmap_size = %" PRIuS, mmap_size);
  ignore_result(Execute(mmap_sql.c_str()));

  // Determine if memory-mapping has actually been enabled.  The Execute() above
  // can succeed without changing the amount mapped.
  mmap_enabled_ = false;
  {
    Statement s(GetUniqueStatement("PRAGMA mmap_size"));
    if (s.Step() && s.ColumnInt64(0) > 0)
      mmap_enabled_ = true;
  }

  DCHECK(!memory_dump_provider_);
  memory_dump_provider_.reset(
      new ConnectionMemoryDumpProvider(db_, histogram_tag_));
  base::trace_event::MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      memory_dump_provider_.get(), "sql::Connection", nullptr);

  return true;
}

void Connection::DoRollback() {
  Statement rollback(GetCachedStatement(SQL_FROM_HERE, "ROLLBACK"));

  // Collect the rollback time manually, sql::Statement would register it as
  // query time only.
  const base::TimeTicks before = Now();
  rollback.RunWithoutTimers();
  const base::TimeDelta delta = Now() - before;

  RecordUpdateTime(delta);
  RecordOneEvent(EVENT_ROLLBACK);

  // The cache may have been accumulating dirty pages for commit.  Note that in
  // some cases sql::Transaction can fire rollback after a database is closed.
  if (is_open())
    ReleaseCacheMemoryIfNeeded(false);

  needs_rollback_ = false;
}

void Connection::StatementRefCreated(StatementRef* ref) {
  DCHECK(open_statements_.find(ref) == open_statements_.end());
  open_statements_.insert(ref);
}

void Connection::StatementRefDeleted(StatementRef* ref) {
  StatementRefSet::iterator i = open_statements_.find(ref);
  if (i == open_statements_.end())
    DLOG(FATAL) << "Could not find statement";
  else
    open_statements_.erase(i);
}

void Connection::set_histogram_tag(const std::string& tag) {
  DCHECK(!is_open());
  histogram_tag_ = tag;
}

void Connection::AddTaggedHistogram(const std::string& name,
                                    size_t sample) const {
  if (histogram_tag_.empty())
    return;

  // TODO(shess): The histogram macros create a bit of static storage
  // for caching the histogram object.  This code shouldn't execute
  // often enough for such caching to be crucial.  If it becomes an
  // issue, the object could be cached alongside histogram_prefix_.
  std::string full_histogram_name = name + "." + histogram_tag_;
  base::HistogramBase* histogram =
      base::SparseHistogram::FactoryGet(
          full_histogram_name,
          base::HistogramBase::kUmaTargetedHistogramFlag);
  if (histogram)
    histogram->Add(sample);
}

int Connection::OnSqliteError(
    int err, sql::Statement *stmt, const char* sql) const {
  UMA_HISTOGRAM_SPARSE_SLOWLY("Sqlite.Error", err);
  AddTaggedHistogram("Sqlite.Error", err);

  // Always log the error.
  if (!sql && stmt)
    sql = stmt->GetSQLStatement();
  if (!sql)
    sql = "-- unknown";

  std::string id = histogram_tag_;
  if (id.empty())
    id = DbPath().BaseName().AsUTF8Unsafe();
  LOG(ERROR) << id << " sqlite error " << err
             << ", errno " << GetLastErrno()
             << ": " << GetErrorMessage()
             << ", sql: " << sql;

  if (!error_callback_.is_null()) {
    // Fire from a copy of the callback in case of reentry into
    // re/set_error_callback().
    // TODO(shess): <http://crbug.com/254584>
    ErrorCallback(error_callback_).Run(err, stmt);
    return err;
  }

  // The default handling is to assert on debug and to ignore on release.
  if (!IsExpectedSqliteError(err))
    DLOG(FATAL) << GetErrorMessage();
  return err;
}

bool Connection::FullIntegrityCheck(std::vector<std::string>* messages) {
  return IntegrityCheckHelper("PRAGMA integrity_check", messages);
}

bool Connection::QuickIntegrityCheck() {
  std::vector<std::string> messages;
  if (!IntegrityCheckHelper("PRAGMA quick_check", &messages))
    return false;
  return messages.size() == 1 && messages[0] == "ok";
}

std::string Connection::GetDiagnosticInfo(int extended_error,
                                          Statement* statement) {
  // Prevent reentrant calls to the error callback.
  ErrorCallback original_callback = std::move(error_callback_);
  reset_error_callback();

  // Trim extended error codes.
  const int error = (extended_error & 0xFF);
  // CollectCorruptionInfo() is implemented in terms of sql::Connection,
  // TODO(shess): Rewrite IntegrityCheckHelper() in terms of raw SQLite.
  std::string result = (error == SQLITE_CORRUPT)
                           ? CollectCorruptionInfo()
                           : CollectErrorInfo(extended_error, statement);

  // The following queries must be executed after CollectErrorInfo() above, so
  // if they result in their own errors, they don't interfere with
  // CollectErrorInfo().
  const bool has_valid_header =
      (ExecuteAndReturnErrorCode("PRAGMA auto_vacuum") == SQLITE_OK);
  const bool select_sqlite_master_result =
      (ExecuteAndReturnErrorCode("SELECT COUNT(*) FROM sqlite_master") ==
       SQLITE_OK);

  // Restore the original error callback.
  error_callback_ = std::move(original_callback);

  base::StringAppendF(&result, "Has valid header: %s\n",
                      (has_valid_header ? "Yes" : "No"));
  base::StringAppendF(&result, "Has valid schema: %s\n",
                      (select_sqlite_master_result ? "Yes" : "No"));

  return result;
}

// TODO(shess): Allow specifying maximum results (default 100 lines).
bool Connection::IntegrityCheckHelper(
    const char* pragma_sql,
    std::vector<std::string>* messages) {
  messages->clear();

  // This has the side effect of setting SQLITE_RecoveryMode, which
  // allows SQLite to process through certain cases of corruption.
  // Failing to set this pragma probably means that the database is
  // beyond recovery.
  const char kWritableSchema[] = "PRAGMA writable_schema = ON";
  if (!Execute(kWritableSchema))
    return false;

  bool ret = false;
  {
    sql::Statement stmt(GetUniqueStatement(pragma_sql));

    // The pragma appears to return all results (up to 100 by default)
    // as a single string.  This doesn't appear to be an API contract,
    // it could return separate lines, so loop _and_ split.
    while (stmt.Step()) {
      std::string result(stmt.ColumnString(0));
      *messages = base::SplitString(result, "\n", base::TRIM_WHITESPACE,
                                    base::SPLIT_WANT_ALL);
    }
    ret = stmt.Succeeded();
  }

  // Best effort to put things back as they were before.
  const char kNoWritableSchema[] = "PRAGMA writable_schema = OFF";
  ignore_result(Execute(kNoWritableSchema));

  return ret;
}

base::TimeTicks TimeSource::Now() {
  return base::TimeTicks::Now();
}

}  // namespace sql
