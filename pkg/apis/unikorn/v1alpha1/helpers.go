/*
Copyright 2025 the Unikorn Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	unikornv1core "github.com/unikorn-cloud/core/pkg/apis/unikorn/v1alpha1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	ErrReference = errors.New("resource reference error")

	ErrReadLength = errors.New("read length not as expected")

	ErrValidation = errors.New("validation error")
)

// Paused implements the ReconcilePauser interface.
func (c *OAuth2Client) Paused() bool {
	return false
}

// StatusConditionRead scans the status conditions for an existing condition whose type
// matches.
func (c *OAuth2Client) StatusConditionRead(t unikornv1core.ConditionType) (*unikornv1core.Condition, error) {
	return unikornv1core.GetCondition(c.Status.Conditions, t)
}

// StatusConditionWrite either adds or updates a condition in the cluster manager status.
// If the condition, status and message match an existing condition the update is
// ignored.
func (c *OAuth2Client) StatusConditionWrite(t unikornv1core.ConditionType, status corev1.ConditionStatus, reason unikornv1core.ConditionReason, message string) {
	unikornv1core.UpdateCondition(&c.Status.Conditions, t, status, reason, message)
}

// ResourceLabels generates a set of labels to uniquely identify the resource
// if it were to be placed in a single global namespace.
func (c *OAuth2Client) ResourceLabels() (labels.Set, error) {
	//nolint:nilnil
	return nil, nil
}

func (u *User) Session(clientID string) (*UserSession, error) {
	index := slices.IndexFunc(u.Spec.Sessions, func(session UserSession) bool {
		return session.ClientID == clientID
	})

	if index < 0 {
		return nil, ErrReference
	}

	return &u.Spec.Sessions[index], nil
}

const (
	// saltLength is the number of bytes of cryptographically random data
	// for salted hashing.  128 bits is recommended by NIST.
	// See https://en.wikipedia.org/wiki/PBKDF2 for more details.
	saltLength = 16

	// hashIterations defines the number of iterations for a salted hash
	// function.  The bigger the number, the harder to exhaustively search
	// but also the longer it takes to compute.
	// See https://en.wikipedia.org/wiki/PBKDF2 for more details.
	// However... we are just hashing a JWE encoded token, not a password,
	// thus it's already a millin times harder to guess than a password!
	hashIterations = 1

	// algorithmSha512 indicates the sha512 hashing algorithm.
	algorithmSha512 = "sha512"
)

// Set encodes the raw value as a PBKDF2 key.
func (t *Token) Set(value string) error {
	salt := make([]byte, saltLength)

	if n, err := rand.Read(salt); err != nil {
		return err
	} else if n != saltLength {
		return fmt.Errorf("%w: unable to create salt for token hashing", ErrReadLength)
	}

	key, err := pbkdf2.Key(sha512.New, value, salt, hashIterations, sha512.Size)
	if err != nil {
		return err
	}

	encoding := algorithmSha512 + "$" + base64.RawURLEncoding.EncodeToString(salt) + "$" + strconv.Itoa(hashIterations) + "$" + base64.RawURLEncoding.EncodeToString(key)

	*t = Token(encoding)

	return nil
}

// Validate checks the provided value matches the hashed value in persistent
// storage.
func (t *Token) Validate(value string) error {
	encoding := string(*t)

	// TODO: this aids in the transition and can be removed soon after.
	// Like 3 months after (by default) given the lifetime of service
	// account tokens.
	if !strings.Contains(encoding, "$") {
		if value != encoding {
			return fmt.Errorf("%w: plantext token values do not match", ErrValidation)
		}

		return nil
	}

	parts := strings.Split(encoding, "$")

	if len(parts) != 4 {
		return fmt.Errorf("%w: token encoding malformed", ErrValidation)
	}

	algorithm := parts[0]
	if algorithm != algorithmSha512 {
		return fmt.Errorf("%w: unsupported hash algorithm %s", ErrValidation, algorithm)
	}

	salt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}

	iterations, err := strconv.Atoi(parts[2])
	if err != nil {
		return err
	}

	hash, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return err
	}

	key, err := pbkdf2.Key(sha512.New, value, salt, iterations, sha512.Size)
	if err != nil {
		return err
	}

	if !bytes.Equal(hash, key) {
		return fmt.Errorf("%w: token mismatch", ErrValidation)
	}

	return nil
}

// Clear resets a token.
func (t *Token) Clear() {
	*t = Token("")
}
