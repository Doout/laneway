package controller

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Doout/laneway/go/internal/identity"
)

const (
	currentSchemaVersion = 11
	busyTimeoutMS        = 5_000
)

type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens or creates a SQLite controller database and applies all known
// migrations. SQLite pragmas are encoded in the DSN so that they apply to every
// connection database/sql may create.
func Open(ctx context.Context, path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: empty database path", ErrInvalid)
	}
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
	q.Add("_pragma", "journal_mode(WAL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open controller database: %w", err)
	}
	// A controller is write-light. One writer makes compound operations
	// deterministic and avoids surfacing SQLITE_BUSY while concurrent callers
	// still queue safely in database/sql.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, now: func() time.Time { return time.Now().UTC().Truncate(time.Second) }}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping controller database: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_versions`).Scan(&version); err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return version, nil
}

func newID() (identity.ID, error) { return identity.NewID() }

func idBytes[T ~[16]byte](id T) []byte {
	b := make([]byte, len(id))
	copy(b, id[:])
	return b
}

func scanID(src []byte) (identity.ID, error) {
	if len(src) != identity.IDSize {
		return identity.ID{}, fmt.Errorf("corrupt ID length %d", len(src))
	}
	var id identity.ID
	copy(id[:], src)
	if id.IsZero() {
		return identity.ID{}, errors.New("corrupt zero ID")
	}
	return id, nil
}

func unix(t time.Time) int64     { return t.UTC().Unix() }
func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func latestTime(base time.Time, candidates ...time.Time) time.Time {
	result := base.UTC()
	for _, candidate := range candidates {
		candidate = candidate.UTC()
		if candidate.After(result) {
			result = candidate
		}
	}
	return result
}

func nullableTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromUnix(v.Int64)
	return &t
}

func validateName(kind, name string) error {
	if name != strings.TrimSpace(name) || name == "" || len(name) > MaxNameLength || strings.IndexByte(name, 0) >= 0 {
		return fmt.Errorf("%w: %s name must be 1..%d trimmed bytes", ErrInvalid, kind, MaxNameLength)
	}
	return nil
}

func isConstraint(err error) bool {
	if err == nil {
		return false
	}
	// modernc exposes numeric errors, but matching the stable SQLite constraint
	// text avoids coupling the package API to driver-specific types.
	return strings.Contains(strings.ToLower(err.Error()), "constraint failed")
}
