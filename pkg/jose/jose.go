/*
Copyright 2022-2024 EscherCloud.
Copyright 2024 the Unikorn Authors.

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

package jose

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/spf13/pflag"

	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"
	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")

	// ErrMissingKey is raised when a key is missing from a secret.
	ErrMissingKey = errors.New("failed to lookup key")

	// ErrContextError is raised when a required value cannot be retrieved
	// from a context.
	ErrContextError = errors.New("value missing from context")
)

type Options struct {
	// IssuerSecretName is the name of the secret that contains our managed
	// signing key.
	IssuerSecretName string

	// RotationPeriod is used to tweak the period for certificate rotation
	// detection.
	RotationPeriod time.Duration
}

// AddFlags registers flags with the provided flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.IssuerSecretName, "jose-tls-secret", "", "TLS sgning key used for JWS/JWE.")
	f.DurationVar(&o.RotationPeriod, "jose-tls-rotation-period", time.Minute, "How often to poll for signing key updates")
}

// JWTIssuer is in charge of API token issue and verification.
// It is expected that the keys come from a mounted kubernetes.io/tls
// secret, and that is managed by cert-manager.  As a result the keys
// will rotate every 60 days (by default), so you MUST ensure they are
// not cached in perpetuity.  Additionally, due to horizontal scale-out
// these secrets need to be shared between all replicas so that a token
// issued by one, can be verified by another.  As such if you ever do
// cache the certificate load, it will need to be coordinated between
// all instances.
type JWTIssuer struct {
	options *Options

	// client is the Kubernetes client for certificate management.
	client client.Client

	// namespace is where we are running so we can find leases and secrets.
	namespace string
}

// NewJWTIssuer returns a new JWT issuer and validator.
func NewJWTIssuer(client client.Client, namespace string, options *Options) *JWTIssuer {
	return &JWTIssuer{
		client:    client,
		namespace: namespace,
		options:   options,
	}
}

type CoordinationClientGetter interface {
	Client() (coordinationv1.CoordinationV1Interface, error)
}

type InClusterCoordinationClientGetter struct{}

func (*InClusterCoordinationClientGetter) Client() (coordinationv1.CoordinationV1Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	coordination, err := coordinationv1.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return coordination, nil
}

// Run starts the certificate management loop.
// The certificate itself is managed by cert-manager, as a reissue duration of N
// and a lifetime of 2N.  Tokens may be issued for a maximum duration of N.  Tokens
// issued just before the certificates N will be able to be verified until their
// expiration.  Now, to pull this off we need to:
//
//   - Keep a primary copy of the current key pair so we can see when it changes.
//     with reference to the master copy managed by cert-manager.
//   - When it does change, we need to demote the primary copy to the secondary,
//     then update the new primary.
//
// Tokens will always be issued by the current primary, but may be verified by
// either the primary or secondary.
//
// As identity is hoizontally scalable, we have another pain in the arse that
// is split brain, so use leadership election to ease the burden.
func (i *JWTIssuer) Run(ctx context.Context, coordinationClientGetter CoordinationClientGetter) error {
	coordination, err := coordinationClientGetter.Client()
	if err != nil {
		return err
	}

	id, err := os.Hostname()
	if err != nil {
		return err
	}

	id += "_" + string(uuid.NewUUID())

	// TODO: logging is not in JSON and breaks jq.
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Namespace: i.namespace,
			Name:      "unikorn-identity-jose-tls",
		},
		Client: coordination,
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	lec := leaderelection.LeaderElectionConfig{
		Lock:          lock,
		LeaseDuration: 15 * time.Second,
		RenewDeadline: 10 * time.Second,
		RetryPeriod:   2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: i.StartLeading,
			OnStoppedLeading: i.StopLeading,
		},
	}

	elector, err := leaderelection.NewLeaderElector(lec)
	if err != nil {
		return err
	}

	go elector.Run(ctx)

	return nil
}

func (i *JWTIssuer) GetPrimaryKeyName() string {
	return i.options.IssuerSecretName + "-primary"
}

func (i *JWTIssuer) GetSecondaryKeyName() string {
	return i.options.IssuerSecretName + "-secondary"
}

func (i *JWTIssuer) getKey(ctx context.Context, name string, secret *corev1.Secret) error {
	if err := i.client.Get(ctx, client.ObjectKey{Namespace: i.namespace, Name: name}, secret); err != nil && !kerrors.IsNotFound(err) {
		return err
	}

	return nil
}

// StartLeading does certificate rotation handling.
// NOTE: there is a startup penalty waiting for the first tick, but on the first
// invocation it's expected there won't be any traffic immediately anyway.
func (i *JWTIssuer) StartLeading(ctx context.Context) {
	log := log.FromContext(ctx)

	ticker := time.NewTicker(i.options.RotationPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// This is obviously Sweet Baby Ray's
			var secretSource corev1.Secret

			if err := i.getKey(ctx, i.options.IssuerSecretName, &secretSource); err != nil {
				log.Error(err, "failed to get JOSE secret source")
				break
			}

			primaryKey := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: i.namespace,
					Name:      i.GetPrimaryKeyName(),
				},
			}

			if err := i.getKey(ctx, i.GetPrimaryKeyName(), &primaryKey); err != nil {
				log.Error(err, "failed to get JOSE primary key")
				break
			}

			// Check if the soure has been rotated, this will be true of the primary
			// doesn't exist yet as its data will be nil.
			sourceRotated := !reflect.DeepEqual(secretSource.Data, primaryKey.Data)

			// If the key pair has been rotated, and the primary actually exists,
			// then we need to copy it to the secondary to keep that alive for
			// verification of currently issued tokens.
			if sourceRotated && primaryKey.ResourceVersion != "" {
				secondaryKey := corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: i.namespace,
						Name:      i.GetSecondaryKeyName(),
					},
				}

				mutate := func() error {
					secondaryKey.Type = corev1.SecretTypeTLS
					secondaryKey.Data = primaryKey.Data

					return nil
				}

				result, err := controllerutil.CreateOrUpdate(ctx, i.client, &secondaryKey, mutate)
				log.Info("JOSE secondary key recociled", "action", result)

				if err != nil {
					log.Error(err, "failed to update JOSE secondary key")
					break
				}
			}

			// The primary is always a copy of the source.
			mutate := func() error {
				primaryKey.Type = corev1.SecretTypeTLS
				primaryKey.Data = secretSource.Data

				return nil
			}

			result, err := controllerutil.CreateOrUpdate(ctx, i.client, &primaryKey, mutate)
			log.Info("JOSE primary key recociled", "action", result)

			if err != nil {
				log.Error(err, "failed to update JOSE primary key")
				break
			}
		}
	}
}

func (i *JWTIssuer) StopLeading() {
}

func parsePrivatekey(pemData []byte) (crypto.PrivateKey, error) {
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: Key encoding has extra data", ErrKeyFormat)
	}

	switch block.Type {
	// PKCS1
	case "RSA PRIVATE KEY":
		return nil, fmt.Errorf("%w: RSA key unsupported", ErrKeyFormat)
	// PKCS8
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	// SEC1
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	return nil, fmt.Errorf("%w: unknown key type %s", ErrKeyFormat, block.Type)
}

func parseCertificate(pemData []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemData)
	if len(rest) > 0 {
		return nil, fmt.Errorf("%w: Key encoding has extra data", ErrKeyFormat)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: unknown certificate type %s", ErrKeyFormat, block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

func getKeyID(cert *x509.Certificate) string {
	kid := sha256.Sum256(cert.RawSubjectPublicKeyInfo)

	return base64.RawURLEncoding.EncodeToString(kid[:])
}

type KeyPair struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey
}

// GetKeyPair returns the public key, private key and key id from the configuration data.
// The key id is inspired by X.509 subject key identifiers, so a hash over the subject public
// key info.
func (i *JWTIssuer) GetKeyPair(ctx context.Context, name string) (*KeyPair, error) {
	var secret corev1.Secret

	if err := i.client.Get(ctx, client.ObjectKey{Namespace: i.namespace, Name: name}, &secret); err != nil {
		return nil, err
	}

	key, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("%w: JOSE secret does not contain tls.key", ErrMissingKey)
	}

	privateKey, err := parsePrivatekey(key)
	if err != nil {
		return nil, err
	}

	cert, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("%w: JOSE secret does not contain tls.crt", ErrMissingKey)
	}

	certificate, err := parseCertificate(cert)
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{
		Cert: certificate,
		Key:  privateKey,
	}

	return keyPair, nil
}

// GetKeyPairs returns all key pairs that exist.
func (i *JWTIssuer) GetKeyPairs(ctx context.Context) []*KeyPair {
	var keyPairs []*KeyPair

	for _, name := range []string{i.GetPrimaryKeyName(), i.GetSecondaryKeyName()} {
		if keyPair, err := i.GetKeyPair(ctx, name); err == nil {
			keyPairs = append(keyPairs, keyPair)
		}
	}

	return keyPairs
}

func (i *JWTIssuer) EncodeJWT(ctx context.Context, claims interface{}) (string, error) {
	keyPair, err := i.GetKeyPair(ctx, i.GetPrimaryKeyName())
	if err != nil {
		return "", fmt.Errorf("failed to get key pair: %w", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES512,
		Key:       keyPair.Key,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	return jwt.Signed(signer).Claims(claims).CompactSerialize()
}

func (i *JWTIssuer) decodeJWT(keyPair *KeyPair, tokenString string, claims interface{}) error {
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return err
	}

	if err := token.Claims(keyPair.Cert.PublicKey, claims); err != nil {
		return err
	}

	return nil
}

func (i *JWTIssuer) DecodeJWT(ctx context.Context, tokenString string, claims interface{}) error {
	for _, keyPair := range i.GetKeyPairs(ctx) {
		if err := i.decodeJWT(keyPair, tokenString, claims); err == nil {
			return nil
		}
	}

	return fmt.Errorf("%w: token cannot be validated against any key", ErrTokenVerification)
}

// TokenType is used to define the specific use of a token.
type TokenType string

const (
	// TokenTypeAccessToken is defined by RFC9068 to prevent reuse in other contexts.
	TokenTypeAccessToken TokenType = "at+jwt"

	// TokenTypeAuthorizationCode is defined by us to prevent reuse in other contexts.
	//nolint:gosec
	TokenTypeAuthorizationCode TokenType = "unikorn-cloud.org/authcode+jwt"

	// TokenTypeLoginState is deinfed by us to prevent reuse in other contexts.
	//nolint:gosec
	TokenTypeLoginState TokenType = "unikorn-cloud.org/loginstate+jwt"

	// TokenTypeRefreshToken is defined to prevent reuse in other contexts.
	//nolint:gosec
	TokenTypeRefreshToken TokenType = "unikorn-cloud.org/rt+jwt"
)

// EncodeJWEToken encodes, signs and encrypts as set of claims.
// For access tokens this implemenrs https://datatracker.ietf.org/doc/html/rfc9068
func (i *JWTIssuer) EncodeJWEToken(ctx context.Context, claims interface{}, tokenType TokenType) (string, error) {
	// TODO: according to the spec we MUST support RS256, but we do both
	// issue and verification, so not strictly necessary.
	keyPair, err := i.GetKeyPair(ctx, i.GetPrimaryKeyName())
	if err != nil {
		return "", fmt.Errorf("failed to get key pair: %w", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES512,
		Key:       keyPair.Key,
	}

	signer, err := jose.NewSigner(signingKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	recipient := jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       keyPair.Cert.PublicKey,
		KeyID:     getKeyID(keyPair.Cert),
	}

	encrypterOptions := &jose.EncrypterOptions{}
	encrypterOptions = encrypterOptions.WithType(jose.ContentType(tokenType)).WithContentType("JWT")

	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, encrypterOptions)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	token, err := jwt.SignedAndEncrypted(signer, encrypter).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	return token, nil
}

func (i *JWTIssuer) decodeJWEToken(keyPair *KeyPair, tokenString string, claims interface{}, tokenType TokenType) error {
	// Parse and decrypt the JWE token with the private key.
	nestedToken, err := jwt.ParseSignedAndEncrypted(tokenString)
	if err != nil {
		return fmt.Errorf("failed to parse encrypted token: %w", err)
	}

	if len(nestedToken.Headers) != 1 {
		return fmt.Errorf("%w: expected exactly one header", ErrTokenVerification)
	}

	t, ok := nestedToken.Headers[0].ExtraHeaders["typ"].(string)
	if !ok {
		return fmt.Errorf("%w: typ header not present", ErrTokenVerification)
	}

	if t != string(tokenType) {
		return fmt.Errorf("%w: typ header incorrect", ErrTokenVerification)
	}

	token, err := nestedToken.Decrypt(keyPair.Key)
	if err != nil {
		return fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Parse and verify the claims with the public key.
	if err := token.Claims(keyPair.Cert.PublicKey, claims); err != nil {
		return fmt.Errorf("failed to decrypt claims: %w", err)
	}

	return nil
}

func (i *JWTIssuer) DecodeJWEToken(ctx context.Context, tokenString string, claims interface{}, tokenType TokenType) error {
	for _, keyPair := range i.GetKeyPairs(ctx) {
		if err := i.decodeJWEToken(keyPair, tokenString, claims, tokenType); err == nil {
			return nil
		}
	}

	return fmt.Errorf("%w: token cannot be validated against any key", ErrTokenVerification)
}

func (i *JWTIssuer) JWKS(ctx context.Context) (*jose.JSONWebKeySet, error) {
	jwks := &jose.JSONWebKeySet{}

	for _, keyPair := range i.GetKeyPairs(ctx) {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   keyPair.Cert.PublicKey,
			KeyID: getKeyID(keyPair.Cert),
			Use:   "sig",
		})
	}

	return jwks, nil
}
