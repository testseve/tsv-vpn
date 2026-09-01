package web

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"tsv-vpn/internal/db"
)

const (
	passwordSetting = "admin_password_hash"
	minPassword     = 10
)

// With no hash in the environment or the database the UI stays in setup mode
// until a password is chosen.
type Credentials struct {
	Store   *db.Store
	EnvHash []byte
}

func (c *Credentials) Hash() []byte {
	if len(c.EnvHash) > 0 {
		return c.EnvHash
	}
	if c.Store == nil {
		return nil
	}
	stored, err := c.Store.Setting(passwordSetting)
	if err != nil {
		return nil
	}
	return []byte(stored)
}

func (c *Credentials) NeedsSetup() bool { return len(c.Hash()) == 0 }

// The environment hash wins when set, so a UI-chosen password would be ignored
// and is refused instead of silently stored.
func (c *Credentials) Set(password string) error {
	if len(c.EnvHash) > 0 {
		return errors.New("the admin password comes from ADMIN_PASSWORD_HASH and cannot be changed here")
	}
	if c.Store == nil {
		return errors.New("no database to store the password in")
	}
	if len([]rune(password)) < minPassword {
		return fmt.Errorf("the password must be at least %d characters", minPassword)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return c.Store.SetSetting(passwordSetting, string(hash))
}

// Clear puts the container back in setup mode; the recovery path for a lost
// password.
func (c *Credentials) Clear() error {
	if c.Store == nil {
		return errors.New("no database to clear the password from")
	}
	return c.Store.DeleteSetting(passwordSetting)
}

func (c *Credentials) Matches(password string) bool {
	hash := c.Hash()
	return len(hash) > 0 && bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
