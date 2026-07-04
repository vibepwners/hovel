package sqlite

import (
	"database/sql"
	"errors"
	"log"
)

func logSQLiteError(action string, err error) {
	if err != nil {
		log.Printf("hovel sqlite storage: %s: %v", action, err)
	}
}

func logSQLiteRollback(action string, err error) {
	if err != nil && !errors.Is(err, sql.ErrTxDone) {
		log.Printf("hovel sqlite storage: %s: %v", action, err)
	}
}
