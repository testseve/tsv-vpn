package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"tsv-vpn/internal/crypto"
	"tsv-vpn/internal/db"
	"tsv-vpn/internal/web"
)

// Generates the bcrypt hash ADMIN_PASSWORD_HASH wants, so no external bcrypt
// tool is needed.
func hashPassword(args []string) error {
	password := ""
	switch {
	case len(args) > 0:
		password = args[0]
	default:
		read, err := io.ReadAll(bufio.NewReader(os.Stdin))
		if err != nil {
			return err
		}
		password = strings.TrimRight(string(read), "\r\n")
	}
	if password == "" {
		return fmt.Errorf("usage: tsv-vpn hash-password <password>, or pipe the password on stdin")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	fmt.Println(string(hash))
	return nil
}

// Recovery for a forgotten UI password: clear it and the setup page comes
// back.
func resetPassword() error {
	key, err := crypto.LoadKey(env("MASTER_KEY_FILE", "/run/secrets/tsv_vpn_master_key"))
	if err != nil {
		return err
	}
	cipher, err := crypto.New(key)
	if err != nil {
		return err
	}
	store, err := db.Open(env("TSV_VPN_DB", "/data/tsv-vpn.db"), cipher)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := (&web.Credentials{Store: store}).Clear(); err != nil {
		return err
	}
	fmt.Println("admin password cleared; the ui asks for a new one on the next visit")
	return nil
}
