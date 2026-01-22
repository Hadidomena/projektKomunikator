package handlers

import (
	"database/sql"

	"github.com/Hadidomena/projektKomunikator/csrf"
	"github.com/Hadidomena/projektKomunikator/validation"
)

type HandlerContext struct {
	DB           *sql.DB
	CSRFStore    *csrf.TokenStore
	LoginTracker *validation.LoginAttemptTracker
}

var ctx *HandlerContext

func Initialize(db *sql.DB, csrfStore *csrf.TokenStore, loginTracker *validation.LoginAttemptTracker) {
	ctx = &HandlerContext{
		DB:           db,
		CSRFStore:    csrfStore,
		LoginTracker: loginTracker,
	}
}

func GetContext() *HandlerContext {
	return ctx
}
