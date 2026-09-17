package auth

import (
	"strings"
	"testing"
)

func TestLoginAndLogout(t *testing.T) {
	s := NewStore(0)
	if err := s.AddUser("1", "admin", "correct horse battery staple", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if hash := s.users["admin"].PasswordHash; !strings.HasPrefix(hash, "$argon2id$") || strings.Contains(hash, "correct horse") {
		t.Fatalf("password was not stored as an Argon2id hash: %q", hash)
	}
	if _, _, err := s.Login("admin", "wrong password"); err == nil {
		t.Fatal("wrong password was accepted")
	}
	token, user, err := s.Login("admin", "correct horse battery staple")
	if err != nil || user.Role != RoleAdmin || token == "" {
		t.Fatalf("login failed: %v", err)
	}
	if _, ok := s.Validate(token); !ok {
		t.Fatal("token rejected")
	}
	s.Logout(token)
	if _, ok := s.Validate(token); ok {
		t.Fatal("token accepted after logout")
	}
}

func TestUserLifecycleKeepsAnEnabledAdmin(t *testing.T) {
	s := NewStore(0)
	if err := s.AddUser("admin", "admin", "a sufficiently long password", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("viewer", "analyst", "another sufficiently long password", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateUser("viewer", "operator", "", RoleOperator, true); err != nil {
		t.Fatal(err)
	}
	updated, ok := s.Get("viewer")
	if !ok || updated.Username != "operator" || updated.Role != RoleOperator {
		t.Fatalf("unexpected updated user: %#v", updated)
	}
	if err := s.DeleteUser("admin"); err == nil {
		t.Fatal("last enabled admin was deleted")
	}
	if err := s.DeleteUser("viewer"); err != nil {
		t.Fatal(err)
	}
	if got := len(s.List()); got != 1 {
		t.Fatalf("user count=%d", got)
	}
}
