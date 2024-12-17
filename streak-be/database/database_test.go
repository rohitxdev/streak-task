package database_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rohitxdev/go-api-starter/database"
	"github.com/stretchr/testify/assert"
)

func TestSqlite(t *testing.T) {
	dbPath := filepath.Join(database.SQLiteDir, "test.db")
	t.Run("Create DB", func(t *testing.T) {
		db, err := database.NewSQLite(dbPath)
		assert.NoError(t, err)
		defer func() {
			db.Close()
			os.RemoveAll(".local")
		}()
	})
}
