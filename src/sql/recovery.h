// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SQL_RECOVERY_H_
#define SQL_RECOVERY_H_

#include <stddef.h>

#include <memory>

#include "base/macros.h"
#include "sql/connection.h"

namespace base {
class FilePath;
}

namespace sql {

// Recovery module for sql/.  The basic idea is to create a fresh database and
// populate it with the recovered contents of the original database.  If
// recovery is successful, the recovered database is backed up over the original
// database.  If recovery is not successful, the original database is razed.  In
// either case, the original handle is poisoned so that operations on the stack
// do not accidentally disrupt the restored data.
//
// RecoverDatabaseOrRaze() automates this, including recoverying the schema of
// from the suspect database.  If a database requires special handling, such as
// recovering between different schema, or tables requiring post-processing,
// then the module can be used manually like:
//
// {
//   std::unique_ptr<sql::Recovery> r =
//       sql::Recovery::Begin(orig_db, orig_db_path);
//   if (r) {
//     // Create the schema to recover to.  On failure, clear the
//     // database.
//     if (!r.db()->Execute(kCreateSchemaSql)) {
//       sql::Recovery::Unrecoverable(std::move(r));
//       return;
//     }
//
//     // Recover data in "mytable".
//     size_t rows_recovered = 0;
//     if (!r.AutoRecoverTable("mytable", 0, &rows_recovered)) {
//       sql::Recovery::Unrecoverable(std::move(r));
//       return;
//     }
//
//     // Manually cleanup additional constraints.
//     if (!r.db()->Execute(kCleanupSql)) {
//       sql::Recovery::Unrecoverable(std::move(r));
//       return;
//     }
//
//     // Commit the recovered data to the original database file.
//     sql::Recovery::Recovered(std::move(r));
//   }
// }
//
// If Recovered() is not called, then RazeAndClose() is called on
// orig_db.

class SQL_EXPORT Recovery {
 public:
  ~Recovery();

  // This module is intended to be used in concert with a virtual
  // table module (see third_party/sqlite/src/src/recover.c).  If the
  // build defines USE_SYSTEM_SQLITE, this module will not be present.
  // TODO(shess): I am still debating how to handle this - perhaps it
  // will just imply Unrecoverable().  This is exposed to allow tests
  // to adapt to the cases, please do not rely on it in production
  // code.
  static bool FullRecoverySupported();

  // Begin the recovery process by opening a temporary database handle
  // and attach the existing database to it at "corrupt".  To prevent
  // deadlock, all transactions on |connection| are rolled back.
  //
  // Returns NULL in case of failure, with no cleanup done on the
  // original connection (except for breaking the transactions).  The
  // caller should Raze() or otherwise cleanup as appropriate.
  //
  // TODO(shess): Later versions of SQLite allow extracting the path
  // from the connection.
  // TODO(shess): Allow specifying the connection point?
  static std::unique_ptr<Recovery> Begin(Connection* connection,
                                         const base::FilePath& db_path)
      WARN_UNUSED_RESULT;

  // Mark recovery completed by replicating the recovery database over
  // the original database, then closing the recovery database.  The
  // original database handle is poisoned, causing future calls
  // against it to fail.
  //
  // If Recovered() is not called, the destructor will call
  // Unrecoverable().
  //
  // TODO(shess): At this time, this function can fail while leaving
  // the original database intact.  Figure out which failure cases
  // should go to RazeAndClose() instead.
  static bool Recovered(std::unique_ptr<Recovery> r) WARN_UNUSED_RESULT;

  // Indicate that the database is unrecoverable.  The original
  // database is razed, and the handle poisoned.
  static void Unrecoverable(std::unique_ptr<Recovery> r);

  // When initially developing recovery code, sometimes the possible
  // database states are not well-understood without further
  // diagnostics.  Abandon recovery but do not raze the original
  // database.
  // NOTE(shess): Only call this when adding recovery support.  In the
  // steady state, all databases should progress to recovered or razed.
  static void Rollback(std::unique_ptr<Recovery> r);

  // Handle to the temporary recovery database.
  sql::Connection* db() { return &recover_db_; }

  // Attempt to recover the named table from the corrupt database into
  // the recovery database using a temporary recover virtual table.
  // The virtual table schema is derived from the named table's schema
  // in database [main].  Data is copied using INSERT OR IGNORE, so
  // duplicates are dropped.
  //
  // If the source table has fewer columns than the target, the target
  // DEFAULT value will be used for those columns.
  //
  // Returns true if all operations succeeded, with the number of rows
  // recovered in |*rows_recovered|.
  //
  // NOTE(shess): Due to a flaw in the recovery virtual table, at this
  // time this code injects the DEFAULT value of the target table in
  // locations where the recovery table returns NULL.  This is not
  // entirely correct, because it happens both when there is a short
  // row (correct) but also where there is an actual NULL value
  // (incorrect).
  //
  // TODO(shess): Flag for INSERT OR REPLACE vs IGNORE.
  // TODO(shess): Handle extended table names.
  bool AutoRecoverTable(const char* table_name, size_t* rows_recovered);

  // Setup a recover virtual table at temp.recover_meta, reading from
  // corrupt.meta.  Returns true if created.
  // TODO(shess): Perhaps integrate into Begin().
  // TODO(shess): Add helpers to fetch additional items from the meta
  // table as needed.
  bool SetupMeta();

  // Fetch the version number from temp.recover_meta.  Returns false
  // if the query fails, or if there is no version row.  Otherwise
  // returns true, with the version in |*version_number|.
  //
  // Only valid to call after successful SetupMeta().
  bool GetMetaVersionNumber(int* version_number);

  // Attempt to recover the database by creating a new database with schema from
  // |db|, then copying over as much data as possible.  After this call, the
  // |db| handle will be poisoned (though technically remaining open) so that
  // future calls will return errors until the handle is re-opened.
  //
  // If a corrupt database contains tables without unique indices, the resulting
  // table may contain duplication.  If this is not acceptable, the client
  // should use the manual process as described in the example at the top of the
  // file, cleaning up data at the appropriate points.
  static void RecoverDatabase(Connection* db, const base::FilePath& db_path);

  // Returns true for SQLite errors which RecoverDatabase() can plausibly fix.
  // This does not guarantee that RecoverDatabase() will successfully recover
  // the database.
  static bool ShouldRecover(int extended_error);

 private:
  explicit Recovery(Connection* connection);

  // Setup the recovery database handle for Begin().  Returns false in
  // case anything failed.
  bool Init(const base::FilePath& db_path) WARN_UNUSED_RESULT;

  // Copy the recovered database over the original database.
  bool Backup() WARN_UNUSED_RESULT;

  // Close the recovery database, and poison the original handle.
  // |raze| controls whether the original database is razed or just
  // poisoned.
  enum Disposition {
    RAZE_AND_POISON,
    POISON,
  };
  void Shutdown(Disposition raze);

  Connection* db_;         // Original database connection.
  Connection recover_db_;  // Recovery connection.

  DISALLOW_COPY_AND_ASSIGN(Recovery);
};

}  // namespace sql

#endif  // SQL_RECOVERY_H_
