package passwordutils

import "testing"

func init() {
	// Load common passwords for tests
	LoadCommonPasswords()
}

func TestCalculatingPasswordStrength(t *testing.T) {
	password1 := "1234"
	password2 := "A1B2./deadline"

	if calculatePasswordStrength(password1) > calculatePasswordStrength(password2) {
		t.Errorf("More complicated password should have higher strength")
	}
}

func TestFindingCommonPassword(t *testing.T) {
	password := "1234"
	if !isCommonPassword(password) {
		t.Errorf("Password '1234' should be recognized as common")
	}
}

func TestTooShortPasword(t *testing.T) {
	password := "123"
	if IsViablePassword(password) != 1 {
		t.Errorf("Password should be too short to pass")
	}
}

func TestThereShouldBeViablePasswords(t *testing.T) {
	password := "A1B2./deadline2137"
	switch IsViablePassword(password) {
	case 1:
		t.Errorf("Password should be long enough")
	case 2:
		t.Errorf("Password should not be common")
	case 3:
		t.Errorf("Password should be strong enough")
	}

}
