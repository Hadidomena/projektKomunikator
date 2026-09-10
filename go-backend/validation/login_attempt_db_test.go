package validation

import (
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func newDBTracker(t *testing.T) (sqlmock.Sqlmock, *LoginAttemptTracker) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	tracker := NewLoginAttemptTracker()
	tracker.SetDB(db)
	return mock, tracker
}

func TestLoginAttemptTrackerDB_CheckAccountStatus_Unlocked(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"is_blocked", "locked_until"}).AddRow(false, nil)
	mock.ExpectQuery("SELECT is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)

	isLocked, _, isBlocked, err := tracker.CheckAccountStatus("user@test.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if isLocked || isBlocked {
		t.Errorf("Expected unlocked, got locked=%v blocked=%v", isLocked, isBlocked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_CheckAccountStatus_Locked(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"is_blocked", "locked_until"}).AddRow(false, time.Now().Add(time.Minute))
	mock.ExpectQuery("SELECT is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)

	isLocked, remaining, isBlocked, err := tracker.CheckAccountStatus("user@test.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !isLocked {
		t.Error("Expected account to be locked")
	}
	if isBlocked {
		t.Error("Expected account not to be blocked")
	}
	if remaining <= 0 || remaining > time.Minute {
		t.Errorf("Expected remaining time ~1 minute, got %v", remaining)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_CheckAccountStatus_Blocked(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"is_blocked", "locked_until"}).AddRow(true, nil)
	mock.ExpectQuery("SELECT is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)

	isLocked, _, isBlocked, err := tracker.CheckAccountStatus("user@test.com")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !isLocked || !isBlocked {
		t.Errorf("Expected locked+blocked, got locked=%v blocked=%v", isLocked, isBlocked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_CheckAccountStatus_DBErrorFailsClosed(t *testing.T) {
	mock, tracker := newDBTracker(t)

	mock.ExpectQuery("SELECT is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnError(fmt.Errorf("db unavailable"))

	isLocked, _, isBlocked, err := tracker.CheckAccountStatus("user@test.com")
	if err == nil {
		t.Error("Expected an error when the DB check fails")
	}
	if isLocked || isBlocked {
		t.Errorf("Expected unknown state on DB error, got locked=%v blocked=%v", isLocked, isBlocked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_RecordFailedAttempt_Locks(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked"}).AddRow(1, false)
	mock.ExpectQuery("UPDATE Users SET failed_login_attempts").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "user@test.com").
		WillReturnRows(rows)

	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt("user@test.com", "192.168.1.1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !isLocked {
		t.Error("Expected account to be locked after first attempt")
	}
	if isBlocked {
		t.Error("Expected account not to be blocked after first attempt")
	}
	if lockDuration != time.Minute {
		t.Errorf("Expected 1 minute lock, got %v", lockDuration)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_RecordFailedAttempt_ThreeAttempts(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked"}).AddRow(3, false)
	mock.ExpectQuery("UPDATE Users SET failed_login_attempts").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "user@test.com").
		WillReturnRows(rows)

	_, lockDuration, _, err := tracker.RecordFailedAttempt("user@test.com", "192.168.1.1")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if lockDuration != 5*time.Minute {
		t.Errorf("Expected 5 minute lock, got %v", lockDuration)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_RecordFailedAttempt_Blocks(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked"}).AddRow(5, true)
	mock.ExpectQuery("UPDATE Users SET failed_login_attempts").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "user@test.com").
		WillReturnRows(rows)

	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt("user@test.com", "192.168.1.1")
	if err == nil {
		t.Error("Expected error for permanently blocked account")
	}
	if !isLocked || !isBlocked {
		t.Errorf("Expected locked+blocked, got locked=%v blocked=%v", isLocked, isBlocked)
	}
	if lockDuration != 0 {
		t.Errorf("Expected 0 lock duration for block, got %v", lockDuration)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_RecordFailedAttempt_AlreadyBlocked(t *testing.T) {
	mock, tracker := newDBTracker(t)

	mock.ExpectQuery("UPDATE Users SET failed_login_attempts").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "user@test.com").
		WillReturnRows(sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked"}))

	isLocked, _, isBlocked, err := tracker.RecordFailedAttempt("user@test.com", "192.168.1.1")
	if err == nil {
		t.Error("Expected error for already blocked account")
	}
	if !isLocked || !isBlocked {
		t.Errorf("Expected locked+blocked, got locked=%v blocked=%v", isLocked, isBlocked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_ResetAttempts(t *testing.T) {
	mock, tracker := newDBTracker(t)

	mock.ExpectExec("UPDATE Users SET failed_login_attempts = 0, locked_until = NULL WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnResult(sqlmock.NewResult(1, 1))

	tracker.ResetAttempts("user@test.com")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}
