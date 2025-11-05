// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inttest

import (
	"database/sql"
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"

	"github.com/allaboutapps/integresql-client-go"
	"github.com/allaboutapps/integresql-client-go/pkg/util"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func DB(t *testing.T, migrationPath string, migrations fs.FS) *pgxpool.Pool {
	t.Helper()

	require.NotEmpty(t, migrationPath, "migrationPath must not be empty")

	localhost := "127.0.0.1"

	// Look for PGHOST in the environment
	host := util.GetEnv("PGHOST", "postgres_test")
	if host == "" {
		t.Setenv("PGHOST", "postgres_test")
	}
	t.Logf("host: %s, replacing with: %s", host, localhost)

	cfg := integresql.ClientConfig{
		BaseURL:    util.GetEnv("INTEGRESQL_CLIENT_BASE_URL", "http://"+localhost+":5000/api"),
		APIVersion: util.GetEnv("INTEGRESQL_CLIENT_API_VERSION", "v1"),
	}

	c, err := integresql.NewClient(cfg)
	require.NoError(t, err, "cannot create new integresql client")

	// compute a hash over all database related files in your workspace (warm template cache)
	hash, err := util.GetTemplateHash(migrationPath)
	require.NoError(t, err, "cannot get template hash")

	templateConfig, err := c.InitializeTemplate(t.Context(), hash)
	if err != nil && errors.Is(err, integresql.ErrTemplateAlreadyInitialized) {
		// template already initialized
		t.Log("Template already initialized")
	} else {
		require.NoError(t, err, "cannot initialize template")
		t.Logf("creating new template with hash: %s", hash)

		// Set up migrations
		goose.SetBaseFS(migrations)

		err = goose.SetDialect("pgx")
		require.NoError(t, err, "cannot set goose dialect")

		cs := templateConfig.Config.ConnectionString()
		cs = strings.Replace(cs, host, localhost, 1)
		t.Logf("Initializing templates with connection: %s", cs)
		gooseDB, err := goose.OpenDBWithDriver("pgx", cs)
		require.NoError(t, err, "cannot open goose db driver")

		// if migrationPath is a full path, we'll only need the last part
		migrationPath = path.Base(migrationPath)

		err = goose.Up(gooseDB, migrationPath)
		require.NoError(t, err, "Failed to run migrations for path %s", migrationPath)

		err = c.FinalizeTemplate(t.Context(), hash)
		require.NoError(t, err, "cannot finalize template")

		err = gooseDB.Close()
		require.NoError(t, err, "cannot close goose db")

		t.Logf("Template finalized with hash: %s", hash)
	}

	testConfig, err := c.GetTestDatabase(t.Context(), hash)
	require.NoError(t, err, "cannot get test database")

	cs := testConfig.Config.ConnectionString()
	cs = strings.Replace(cs, host, localhost, 1)
	t.Logf("Test database connection: %s", cs)

	// Test if we can connect with a generic sql open
	sconn, err := sql.Open("pgx", cs)
	require.NoError(t, err, "cannot open pgx connection")

	// List all tables in db and print them to the log
	rows, err := sconn.Query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
	require.NoError(t, err, "cannot query tables")
	defer rows.Close()
	found := false
	for rows.Next() {
		found = true
		var table string
		err = rows.Scan(&table)
		require.NoError(t, err, "cannot scan table row")
		t.Logf("Table: %s", table)
	}
	err = rows.Err()
	require.NoError(t, err)

	require.True(t, found, "No tables found, likely your migration wasn't found.")

	err = sconn.Close()
	require.NoError(t, err)

	// Create a pgx connection config
	config, err := pgxpool.ParseConfig(cs)
	require.NoError(t, err)

	conn, err := NewLoggingConn(config)
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
	})
	t.Log("Database connection established")

	return conn
}
