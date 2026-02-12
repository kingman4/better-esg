//go:build integration

package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startPostgres spins up a disposable Postgres container and returns a connected *sql.DB.
func startPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "test",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(30 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start postgres container: %v", err)
	}
	t.Cleanup(func() { container.Terminate(ctx) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("failed to get container host: %v", err)
	}

	port, err := container.MappedPort(ctx, "5432")
	if err != nil {
		t.Fatalf("failed to get container port: %v", err)
	}

	dsn := fmt.Sprintf("postgres://test:test@%s:%s/test?sslmode=disable", host, port.Port())
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	return db
}

func TestMigrationsUp(t *testing.T) {
	db := startPostgres(t)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Verify all expected tables exist
	expectedTables := []string{
		"organizations",
		"users",
		"fda_credentials",
		"submissions",
		"submission_files",
		"acknowledgements",
		"audit_logs",
		"workflow_state_log",
		"notification_preferences",
	}

	for _, table := range expectedTables {
		var exists bool
		err := db.QueryRow(
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)",
			table,
		).Scan(&exists)
		if err != nil {
			t.Errorf("error checking table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("expected table %s to exist, but it doesn't", table)
		}
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	db := startPostgres(t)

	// Run migrations twice — second run should be a no-op
	if err := RunMigrations(db); err != nil {
		t.Fatalf("first migration run failed: %v", err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("second migration run failed (not idempotent): %v", err)
	}
}

func TestMigrationsCreateCorrectColumns(t *testing.T) {
	db := startPostgres(t)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Spot-check critical columns on the submissions table
	expectedColumns := map[string]string{
		"id":              "uuid",
		"org_id":          "uuid",
		"core_id":         "character varying",
		"fda_center":      "character varying",
		"submission_type": "character varying",
		"status":          "character varying",
		"workflow_state":  "character varying",
		"payload_id":      "character varying",
		"file_count":      "integer",
		"total_size_bytes": "bigint",
		"created_at":      "timestamp without time zone",
		"metadata_json":   "jsonb",
	}

	for col, expectedType := range expectedColumns {
		var dataType string
		err := db.QueryRow(
			`SELECT data_type FROM information_schema.columns
			 WHERE table_name = 'submissions' AND column_name = $1`,
			col,
		).Scan(&dataType)
		if err != nil {
			t.Errorf("column submissions.%s: %v", col, err)
			continue
		}
		if dataType != expectedType {
			t.Errorf("submissions.%s: expected type %q, got %q", col, expectedType, dataType)
		}
	}
}

func TestRLSPoliciesExist(t *testing.T) {
	db := startPostgres(t)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("migrations failed: %v", err)
	}

	// Verify RLS is enabled on expected tables
	rlsTables := []string{"submissions", "submission_files", "audit_logs"}
	for _, table := range rlsTables {
		var rlsEnabled bool
		err := db.QueryRow(
			"SELECT rowsecurity FROM pg_tables WHERE tablename = $1",
			table,
		).Scan(&rlsEnabled)
		if err != nil {
			t.Errorf("error checking RLS on %s: %v", table, err)
			continue
		}
		if !rlsEnabled {
			t.Errorf("expected RLS enabled on %s, but it's not", table)
		}
	}

	// Verify policies exist
	expectedPolicies := map[string]string{
		"submissions_org_isolation":      "submissions",
		"submission_files_org_isolation": "submission_files",
		"audit_logs_org_isolation":       "audit_logs",
	}
	for policy, table := range expectedPolicies {
		var exists bool
		err := db.QueryRow(
			"SELECT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = $1 AND tablename = $2)",
			policy, table,
		).Scan(&exists)
		if err != nil {
			t.Errorf("error checking policy %s: %v", policy, err)
			continue
		}
		if !exists {
			t.Errorf("expected policy %s on table %s to exist", policy, table)
		}
	}
}
