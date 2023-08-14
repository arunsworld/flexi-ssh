package main

import (
	"os"

	"github.com/gliderlabs/ssh"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type user struct {
	Username string
	PwdHash  string
	PubKey   string
	// internal
	pubKey ssh.PublicKey
}

type users []user

type auth struct {
	users map[string]user
}

func newUsersFromConfig(f string) (*auth, error) {
	if f == "" {
		return &auth{users: make(map[string]user)}, nil
	}
	contents, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	config := users{}
	if err := yaml.Unmarshal(contents, &config); err != nil {
		return nil, err
	}
	v := make(map[string]user)
	for _, c := range config {
		if c.PubKey != "" {
			pk, err := parseOpenSSHKey(c.PubKey)
			if err != nil {
				return nil, err
			}
			c.pubKey = pk
		}
		v[c.Username] = c
	}
	return &auth{
		users: v,
	}, nil
}

func (a *auth) authenticateWithPwd(user, password string) bool {
	creds, ok := a.users[user]
	if !ok {
		return false
	}
	if creds.PwdHash == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(creds.PwdHash), []byte(password))
	return err == nil
}

func (a *auth) authenticateWithPubKey(user string, key ssh.PublicKey) bool {
	creds, ok := a.users[user]
	if !ok {
		return false
	}
	if creds.pubKey == nil {
		return false
	}
	return ssh.KeysEqual(key, creds.pubKey)
}

func parseOpenSSHKey(key string) (ssh.PublicKey, error) {
	result, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	return result, err
}
