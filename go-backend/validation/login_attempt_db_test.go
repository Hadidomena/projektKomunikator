package validation

import (
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

	isLocked, _, isBlocked := tracker.CheckAccountStatus("user@test.com")
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

	isLocked, remaining, isBlocked := tracker.CheckAccountStatus("user@test.com")
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

	isLocked, _, isBlocked := tracker.CheckAccountStatus("user@test.com")
	if !isLocked || !isBlocked {
		t.Errorf("Expected locked+blocked, got locked=%v blocked=%v", isLocked, isBlocked)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestLoginAttemptTrackerDB_RecordFailedAttempt_Locks(t *testing.T) {
	mock, tracker := newDBTracker(t)

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked", "locked_until"}).AddRow(0, false, nil)
	mock.ExpectQuery("SELECT failed_login_attempts, is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)
	mock.ExpectExec("UPDATE Users SET failed_login_attempts = \\$1, locked_until = \\$2 WHERE email = \\$3").
		WithArgs(1, sqlmock.AnyArg(), "user@test.com").
		WillReturnResult(sqlmock.NewResult(1, 1))

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

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked", "locked_until"}).AddRow(2, false, nil)
	mock.ExpectQuery("SELECT failed_login_attempts, is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)
	mock.ExpectExec("UPDATE Users SET failed_login_attempts = \\$1, locked_until = \\$2 WHERE email = \\$3").
		WithArgs(3, sqlmock.AnyArg(), "user@test.com").
		WillReturnResult(sqlmock.NewResult(1, 1))

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

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked", "locked_until"}).AddRow(4, false, nil)
	mock.ExpectQuery("SELECT failed_login_attempts, is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)
	mock.ExpectExec("UPDATE Users SET failed_login_attempts = \\$1, is_blocked = TRUE, locked_until = NULL WHERE email = \\$2").
		WithArgs(5, "user@test.com").
		WillReturnResult(sqlmock.NewResult(1, 1))

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

	rows := sqlmock.NewRows([]string{"failed_login_attempts", "is_blocked", "locked_until"}).AddRow(5, true, nil)
	mock.ExpectQuery("SELECT failed_login_attempts, is_blocked, locked_until FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)

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
