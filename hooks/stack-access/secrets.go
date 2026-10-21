package main

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Keys of the access Secret.
const (
	keyUsername = "username"
	keyPassword = "password"
	keyEnabled  = "enabled"

	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "stack-access"
)

// Letters and digits only: the password is easy to paste and needs no
// escaping in a URL or a shell.
const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

// credentials is the content of an access Secret.
type credentials struct {
	Username string
	Password string
	Enabled  bool
}

// generatePassword returns a random password of n characters.
func generatePassword(n int) (string, error) {
	if n <= 0 {
		return "", errors.New("password length must be greater than zero")
	}
	max := big.NewInt(int64(len(passwordAlphabet)))
	b := make([]byte, n)
	for i := range b {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = passwordAlphabet[v.Int64()]
	}
	return string(b), nil
}

// readCredentials reads a Secret. A Secret without a password is invalid.
// enabled is true unless the key says false.
func readCredentials(sec *corev1.Secret) (credentials, bool) {
	if sec == nil {
		return credentials{}, false
	}
	c := credentials{
		Username: string(sec.Data[keyUsername]),
		Password: string(sec.Data[keyPassword]),
		Enabled:  true,
	}
	if v, ok := sec.Data[keyEnabled]; ok {
		if b, err := parseBool(string(v)); err == nil {
			c.Enabled = b
		}
	}
	if c.Username == "" || c.Password == "" {
		return credentials{}, false
	}
	return c, true
}

// newAccessSecret builds a new access Secret for a stack namespace.
func newAccessSecret(cfg config, namespace, instance string) (*corev1.Secret, error) {
	pw, err := generatePassword(cfg.PasswordLength)
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfg.SecretName,
			Namespace: namespace,
			Labels:    map[string]string{managedByLabel: managedByValue},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			keyUsername: []byte(instance),
			keyPassword: []byte(pw),
			keyEnabled:  []byte(strconv.FormatBool(cfg.DefaultEnabled)),
		},
	}, nil
}
