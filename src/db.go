package medods_test

import (
	"os"
	"fmt"
    "context"
    "time"

	"github.com/jackc/pgx/v5"
)

type Database interface {
    SetRefreshToken(guid string, refreshHash []byte, expiration time.Time) error
    GetRefreshToken(guid string) (refreshHash []byte, expiration time.Time, err error)
}

type PgxDatabase struct {
    conn *pgx.Conn
}

func NewPgx() (*PgxDatabase, error) {
    // TODO log initializing postgres

    user := os.Getenv("POSTGRES_USER")
    if user == "" {
        return nil, fmt.Errorf("$POSTGRES_USER not set")
    }

    password := os.Getenv("POSTGRES_PASSWORD")
    if password == "" {
        return nil, fmt.Errorf("$POSTGRES_PASSWORD not set")
    }

    pg_address := fmt.Sprintf("postgres://%s:%s@db:5432/credentials", user, password)
    postgres, err := pgx.Connect(context.Background(), pg_address)

    if err != nil {
        return nil, err
    }

    // TODO guid as primary key
    _, err = postgres.Exec(context.Background(), `
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
            guid CHAR(20) NOT NULL,
            token CHAR(60) NOT NULL,
            expires TIMESTAMP NOT NULL
        );
    `)

    if err != nil {
        return nil, err
    }

    // TODO log connected to version X

    return &PgxDatabase{postgres}, nil
}

func (db PgxDatabase) Close() {
    db.conn.Close(context.Background())  // TODO use timeouts
}

func (db PgxDatabase) SetRefreshToken(guid string, refreshHash []byte, expiration time.Time) error {
    _, err := db.conn.Exec(context.Background(), `
        INSERT INTO refresh_tokens (guid, token, expires)
        VALUES ($1, $2, $3);
    `, guid, refreshHash, expiration)
    return err
}

func (db PgxDatabase) GetRefreshToken(guid string) (
    refreshHash []byte, expiration time.Time, err error,
) {
    var hashString string
    err = db.conn.QueryRow(context.Background(), `
        SELECT token, expires FROM refresh_tokens WHERE guid=$1
    `, guid).Scan(&hashString, &expiration)

    return []byte(hashString), expiration, err
}
