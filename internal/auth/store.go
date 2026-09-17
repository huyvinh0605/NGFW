package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory  = 64 * 1024
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
)

type Role string

const (
	RoleAdmin    Role = "ADMIN"
	RoleOperator Role = "OPERATOR"
	RoleViewer   Role = "VIEWER"
)

type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Role         Role   `json:"role"`
	PasswordHash string `json:"-"`
	Enabled      bool   `json:"enabled"`
}
type session struct {
	User      User
	ExpiresAt time.Time
}
type Store struct {
	mu     sync.RWMutex
	users  map[string]User
	tokens map[string]session
	ttl    time.Duration
}

func NewStore(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	return &Store{users: map[string]User{}, tokens: map[string]session{}, ttl: ttl}
}
func (s *Store) AddUser(id, username, password string, role Role) error {
	if id == "" || username == "" || password == "" {
		return errors.New("username and password are required")
	}
	if !validRole(role) {
		return errors.New("invalid role")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return errors.New("username already exists")
	}
	for _, user := range s.users {
		if user.ID == id {
			return errors.New("user id already exists")
		}
	}
	s.users[username] = User{ID: id, Username: username, Role: role, PasswordHash: hash, Enabled: true}
	return nil
}
func (s *Store) Login(username, password string) (string, User, error) {
	s.mu.RLock()
	u, ok := s.users[username]
	s.mu.RUnlock()
	if !ok || !u.Enabled || !verifyPassword(u.PasswordHash, password) {
		return "", User{}, errors.New("invalid credentials")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", User{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	s.tokens[token] = session{User: u, ExpiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return token, u, nil
}
func (s *Store) Validate(token string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.tokens[token]
	if !ok || time.Now().After(v.ExpiresAt) {
		if ok {
			delete(s.tokens, token)
		}
		return User{}, false
	}
	return v.User, true
}
func (s *Store) Logout(token string) { s.mu.Lock(); delete(s.tokens, token); s.mu.Unlock() }

func (s *Store) List() []User {
	s.mu.RLock()
	items := make([]User, 0, len(s.users))
	for _, user := range s.users {
		items = append(items, user)
	}
	s.mu.RUnlock()
	sort.Slice(items, func(i, j int) bool { return items[i].Username < items[j].Username })
	return items
}

func (s *Store) Get(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.ID == id {
			return user, true
		}
	}
	return User{}, false
}

func (s *Store) UpdateUser(id, username, password string, role Role, enabled bool) error {
	if id == "" || username == "" {
		return errors.New("user id and username are required")
	}
	if !validRole(role) {
		return errors.New("invalid role")
	}
	var newHash string
	var err error
	if password != "" {
		newHash, err = hashPassword(password)
		if err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	oldKey := ""
	var current User
	for key, user := range s.users {
		if user.ID == id {
			oldKey, current = key, user
			break
		}
	}
	if oldKey == "" {
		return errors.New("user not found")
	}
	if owner, exists := s.users[username]; exists && owner.ID != id {
		return errors.New("username already exists")
	}
	if current.Role == RoleAdmin && current.Enabled && (role != RoleAdmin || !enabled) && s.enabledAdminsLocked() <= 1 {
		return errors.New("cannot disable or demote the last enabled admin")
	}
	if newHash == "" {
		newHash = current.PasswordHash
	}
	delete(s.users, oldKey)
	s.users[username] = User{ID: id, Username: username, Role: role, PasswordHash: newHash, Enabled: enabled}
	s.invalidateUserLocked(id)
	return nil
}

func (s *Store) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := ""
	var current User
	for username, user := range s.users {
		if user.ID == id {
			key, current = username, user
			break
		}
	}
	if key == "" {
		return errors.New("user not found")
	}
	if current.Role == RoleAdmin && current.Enabled && s.enabledAdminsLocked() <= 1 {
		return errors.New("cannot delete the last enabled admin")
	}
	delete(s.users, key)
	s.invalidateUserLocked(id)
	return nil
}

func validRole(role Role) bool {
	return role == RoleAdmin || role == RoleOperator || role == RoleViewer
}
func (s *Store) enabledAdminsLocked() int {
	count := 0
	for _, user := range s.users {
		if user.Enabled && user.Role == RoleAdmin {
			count++
		}
	}
	return count
}
func (s *Store) invalidateUserLocked(id string) {
	for token, session := range s.tokens {
		if session.User.ID == id {
			delete(s.tokens, token)
		}
	}
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}

func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var iterations uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads); err != nil {
		return false
	}
	if memory < 8*1024 || memory > 1024*1024 || iterations < 1 || iterations > 10 || threads < 1 || threads > 16 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
