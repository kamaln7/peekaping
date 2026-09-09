package bruteforce

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

func setupSQLiteRepo(t *testing.T) Repository {
	sqldb, err := sql.Open(sqliteshim.ShimName, ":memory:")
	require.NoError(t, err)
	db := bun.NewDB(sqldb, sqlitedialect.New())
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`
		CREATE TABLE login_state (
			key TEXT PRIMARY KEY,
			fail_count INTEGER NOT NULL,
			first_fail_at DATETIME NOT NULL,
			locked_until DATETIME
		)
	`)
	require.NoError(t, err)

	return NewSQLRepository(db)
}

// OnFailure must work on SQLite, which has no SELECT ... FOR UPDATE.
func TestSQLiteOnFailureLocksAfterMaxAttempts(t *testing.T) {
	repo := setupSQLiteRepo(t)
	ctx := context.Background()
	now := time.Now()

	for i := 1; i <= 2; i++ {
		locked, _, err := repo.OnFailure(ctx, "1.2.3.4:a@b.c", now, time.Minute, 3, time.Minute)
		require.NoError(t, err)
		require.False(t, locked, "attempt %d", i)
	}

	locked, until, err := repo.OnFailure(ctx, "1.2.3.4:a@b.c", now, time.Minute, 3, time.Minute)
	require.NoError(t, err)
	require.True(t, locked)
	require.True(t, until.After(now))

	isLocked, _, err := repo.IsLocked(ctx, "1.2.3.4:a@b.c")
	require.NoError(t, err)
	require.True(t, isLocked)
}
