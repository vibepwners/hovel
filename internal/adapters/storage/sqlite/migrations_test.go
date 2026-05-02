package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyMigrationsCreatesSchemaAndRecordsChecksums(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	if err := ApplyMigrations(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := ApplyMigrations(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"schema_migrations", "operator_sessions", "throw_plans"} {
		if !tableExists(t, db, table) {
			t.Fatalf("table %s was not created", table)
		}
	}

	var version int
	var name, checksum string
	if err := db.QueryRow(`SELECT version, name, checksum FROM schema_migrations`).Scan(&version, &name, &checksum); err != nil {
		t.Fatal(err)
	}
	if version != 1 || name != Migrations[0].Name || checksum != Migrations[0].Checksum() {
		t.Fatalf("migration record = %d %q %q", version, name, checksum)
	}
}

func TestApplyMigrationsRejectsChangedAppliedMigration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	if err := Apply(context.Background(), db, []Migration{{Version: 1, Name: "one", SQL: `CREATE TABLE one(id INTEGER);`}}); err != nil {
		t.Fatal(err)
	}
	err := Apply(context.Background(), db, []Migration{{Version: 1, Name: "one", SQL: `CREATE TABLE one(id TEXT);`}})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v, want checksum mismatch", err)
	}
}

func TestApplyMigrationsRejectsNonContiguousVersions(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	err := Apply(context.Background(), db, []Migration{{Version: 2, Name: "two", SQL: `CREATE TABLE two(id INTEGER);`}})
	if err == nil || !strings.Contains(err.Error(), "contiguous") {
		t.Fatalf("error = %v, want contiguous version error", err)
	}
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), DatabaseFile))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}

func tableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var name string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
	return err == nil && name == table
}
