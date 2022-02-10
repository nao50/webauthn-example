package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

type User struct {
	id          uint64
	name        string
	displayName string
	credentials []webauthn.Credential
}

func NewUser(name string, displayName string) *User {
	user := &User{}
	user.id = randomUint64()
	user.name = name
	user.displayName = displayName
	// user.credentials = []webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.id))
	return buf
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.name
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.displayName
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.credentials = append(u.credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u User) CredentialExcludeList() []protocol.CredentialDescriptor {

	credentialExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}

	return credentialExcludeList
}

//////////////////////////////////////////////////////////////////////////////
type userdb struct {
	users map[string]*User
	mu    sync.RWMutex
}

var db *userdb

// DB returns a userdb singleton
func newUserDB() *userdb {
	if db == nil {
		db = &userdb{
			users: make(map[string]*User),
		}
	}
	return db
}

// PutUser stores a new user by the user's username
func (db *userdb) PutUser(user *User) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.users[user.name] = user
}

// GetUser returns a *User by the user's username
func (db *userdb) GetUser(name string) (*User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	user, ok := db.users[name]
	if !ok {
		return &User{}, fmt.Errorf("error getting user '%s': does not exist", name)
	}
	return user, nil
}
