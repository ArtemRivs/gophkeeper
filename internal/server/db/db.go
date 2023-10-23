package db

import (
	"github.com/golang-migrate/migrate/v4"
)

// RunMigrations - start migrations
func RunMigrations(dbDSN string) error {
	m, err := migrate.New("file://db/migrations", dbDSN)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}
