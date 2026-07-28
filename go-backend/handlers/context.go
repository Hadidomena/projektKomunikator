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
	E2EEPepper   string
}

var ctx *HandlerContext

func Initialize(db *sql.DB, csrfStore *csrf.TokenStore, loginTracker *validation.LoginAttemptTracker, e2eePepper string) {
	ctx = &HandlerContext{
		DB:           db,
		CSRFStore:    csrfStore,
		LoginTracker: loginTracker,
		E2EEPepper:   e2eePepper,
	}
}

func GetContext() *HandlerContext {
	return ctx
}
