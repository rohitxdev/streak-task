// This package provides an abstraction layer for interacting with the database.
package repo

import (
	"database/sql"
)

type Repo struct {
	db *sql.DB
}

func (repo *Repo) Close() error {
	return repo.db.Close()
}

func New(db *sql.DB) (*Repo, error) {
	r := &Repo{
		db: db,
	}
	return r, nil
}
