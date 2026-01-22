package handlers_test

import (
	"database/sql"
	"testing"

	"github.com/Hadidomena/projektKomunikator/csrf"
	"github.com/Hadidomena/projektKomunikator/handlers"
	"github.com/Hadidomena/projektKomunikator/validation"
)

func TestInitializeAndGetContext(t *testing.T) {
	// Mock dependencies
	var db *sql.DB
	csrfStore := csrf.NewTokenStore()
	loginTracker := validation.NewLoginAttemptTracker()

	// Initialize handlers context
	handlers.Initialize(db, csrfStore, loginTracker)

	// Get context
	ctx := handlers.GetContext()

	if ctx == nil {
		t.Fatal("Context should not be nil after initialization")
	}

	if ctx.DB != db {
		t.Error("DB in context doesn't match initialized DB")
	}

	if ctx.CSRFStore != csrfStore {
		t.Error("CSRFStore in context doesn't match initialized store")
	}

	if ctx.LoginTracker != loginTracker {
		t.Error("LoginTracker in context doesn't match initialized tracker")
	}
}

func TestGetContextBeforeInitialize(t *testing.T) {
	// Reset context by initializing with nil (not recommended in production)
	handlers.Initialize(nil, nil, nil)

	ctx := handlers.GetContext()

	if ctx == nil {
		t.Error("GetContext should return context even if initialized with nil values")
	}
}
