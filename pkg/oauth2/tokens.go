/*
Copyright 2022-2024 EscherCloud.
Copyright 2024-2025 the Unikorn Authors.

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

package oauth2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"

	unikornv1 "github.com/unikorn-cloud/identity/pkg/apis/unikorn/v1alpha1"
	"github.com/unikorn-cloud/identity/pkg/jose"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrKeyFormat is raised when something is wrong with the
	// encryption keys.
	ErrKeyFormat = errors.New("key format error")

	// ErrTokenVerification is raised when token verification fails.
	ErrTokenVerification = errors.New("failed to verify token")
)

type AccessTokenType string

const (
	AccessTokenTypeFederated AccessTokenType = "fed"

	AccessTokenTypeServiceAccount AccessTokenType = "sa"
)

// CustomAccessTokenClaims contains all application specific claims in a single
// top-level claim that won't clash with the ones defined by IETF.
type CustomAccessTokenClaims struct {
	// Type is the type of access token this is.
	Type AccessTokenType `json:"typ"`
	// Provider is the provider name for the token (federated tokens only).
	Provider string `json:"pr"`
	// AccessToken as defined for the IdP (federated tokens only).
	AccessToken string `json:"at"`
	// OrganizationID is the identifier of the organization (service accounts only).
	OrganizationID string `json:"oid"`
	// ClientID is the oauth2 client that the user is using.
	ClientID string `json:"cid"`
}

// AccessTokenClaims is an application specific set of claims.
// TODO: this technically isn't conformant to oauth2 in that we don't specify
// the client_id claim, and there are probably others.
type AccessTokenClaims struct {
	jwt.Claims `json:",inline"`

	Config *AccessTokenConfigClaims `json:"cnf,omitempty"`

	// Custom claims are application specific extensions.
	Custom *CustomAccessTokenClaims `json:"cat,omitempty"`
}

type AccessTokenConfigClaims struct {
	//nolint: tagliatelle
	X509Thumbprint *string `json:"x5t@S256,omitempty"`
}

// CustomRefreshTokenClaims contains all application specific claims in a single
// top-level claim that won't clash with the ones defined by IETF.
type CustomRefreshTokenClaims struct {
	// Provider is the provider name for the token.
	Provider string
	// RefreshToken as defined for the IdP.
	RefreshToken string `json:"rt"`
	// ClientID is the oauth2 client that the user is using.
	ClientID string `json:"cid"`
}

// RefreshTokenClaims is a basic set of JWT claims, plus a wrapper for the
// IdP's refresh token.
type RefreshTokenClaims struct {
	jwt.Claims `json:",inline"`

	// Custom claims are application specific extensions.
	Custom *CustomRefreshTokenClaims `json:"crt,omitempty"`
}

// Tokens is the set of tokens and metadata returned by a token issue.
type Tokens struct {
	Expiry       time.Time
	AccessToken  string
	RefreshToken *string
}

// Federated is any information required to issue a federated access token.
type Federated struct {
	Provider     string
	Expiry       time.Time
	AccessToken  string
	RefreshToken *string
}

// ServiceAccount is any information required to issue a service account access token.
type ServiceAccount struct {
	// OrganizationID is the organization ID used to verify the subject exists
	// and the token is still valid.
	OrganizationID string
	// Duration is the token lifetime.  Please note this should only be used for
	// service account tokens that by definition need to be long lived.
	Duration *time.Duration
}

// IssueInfo controls how the access token is encoded.
type IssueInfo struct {
	// Issuer should be from the HTTP Host header, as requested by the client.
	Issuer string
	// Audience should be from the HTTP Host header, as only we can decipher the token.
	Audience string
	// Subject is the user, or service account ID, the token is valid for.  This is used
	// for RBAC.
	Subject string
	// Federated is a set of tokens, if defined, for a federated OIDC server.
	Federated *Federated
	// ServiceAccount indicates this is issued for a service account.
	ServiceAccount *ServiceAccount
	// X509Thumbprint is a certificate thumbprint for X.509 based passwordless authentication.
	X509Thumbprint string
	// ClientID is the oauth2 client that the user is using.
	ClientID string
}

// expiry calculates when the token should expire.  By default we use the duration
// defined by the authenticator.  If the token is federated, we pick the lower of
// the default, and the expiry time of the federated acces token.  If the token
// is for a service account, these need to be long lived for automation, so we can
// override the default for this only.
func (a *Authenticator) expiry(now time.Time, info *IssueInfo) time.Time {
	if info.ServiceAccount != nil && info.ServiceAccount.Duration != nil {
		return now.Add(*info.ServiceAccount.Duration)
	}

	expiry := now.Add(a.options.AccessTokenDuration)

	if info.Federated != nil && info.Federated.Expiry.Before(expiry) {
		expiry = info.Federated.Expiry
	}

	return expiry
}

// applyCustomClaims adds any custom claims to the access token based on the
// issuer information.
func (a *Authenticator) applyCustomClaims(claims *AccessTokenClaims, info *IssueInfo) {
	switch {
	case info.Federated != nil:
		claims.Custom = &CustomAccessTokenClaims{
			Type:        AccessTokenTypeFederated,
			Provider:    info.Federated.Provider,
			AccessToken: info.Federated.AccessToken,
			ClientID:    info.ClientID,
		}

	case info.ServiceAccount != nil:
		claims.Custom = &CustomAccessTokenClaims{
			Type:           AccessTokenTypeServiceAccount,
			OrganizationID: info.ServiceAccount.OrganizationID,
		}

	case info.X509Thumbprint != "":
		claims.Config = &AccessTokenConfigClaims{
			X509Thumbprint: &info.X509Thumbprint,
		}
	}
}

// Issue issues a new JWT access token.
func (a *Authenticator) Issue(ctx context.Context, info *IssueInfo) (*Tokens, error) {
	now := time.Now()

	expiry := a.expiry(now, info)

	nowRFC7519 := jwt.NewNumericDate(now)
	atExpiresAtRFC7519 := jwt.NewNumericDate(expiry)
	rtExpiresAtRFC7519 := jwt.NewNumericDate(now.Add(a.options.RefreshTokenDuration))

	atClaims := &AccessTokenClaims{
		Claims: jwt.Claims{
			ID:      uuid.New().String(),
			Subject: info.Subject,
			Audience: jwt.Audience{
				info.Audience,
			},
			Issuer:    info.Issuer,
			IssuedAt:  nowRFC7519,
			NotBefore: nowRFC7519,
			Expiry:    atExpiresAtRFC7519,
		},
	}

	a.applyCustomClaims(atClaims, info)

	at, err := a.issuer.EncodeJWEToken(ctx, atClaims, jose.TokenTypeAccessToken)
	if err != nil {
		return nil, err
	}

	tokens := &Tokens{
		AccessToken: at,
		Expiry:      expiry,
	}

	if info.Federated != nil && info.Federated.RefreshToken != nil {
		rtClaims := &RefreshTokenClaims{
			Claims: jwt.Claims{
				ID:      uuid.New().String(),
				Subject: info.Subject,
				Audience: jwt.Audience{
					info.Audience,
				},
				Issuer:    info.Issuer,
				IssuedAt:  nowRFC7519,
				NotBefore: nowRFC7519,
				Expiry:    rtExpiresAtRFC7519,
			},
			Custom: &CustomRefreshTokenClaims{
				Provider:     info.Federated.Provider,
				ClientID:     info.ClientID,
				RefreshToken: *info.Federated.RefreshToken,
			},
		}

		rt, err := a.issuer.EncodeJWEToken(ctx, rtClaims, jose.TokenTypeRefreshToken)
		if err != nil {
			return nil, err
		}

		tokens.RefreshToken = &rt
	}

	return tokens, nil
}

type VerifyInfo struct {
	Issuer   string
	Audience string
	Token    string
}

// Verify checks the access token parses and validates.
func (a *Authenticator) Verify(ctx context.Context, info *VerifyInfo) (*AccessTokenClaims, error) {
	// The verification process is very expensive, so we add a cache in here to
	// improve interactivity.  Once this is in place, then the network latency becomes
	// the bottle neck, presumably this is the TLS handshake.  Similar code can be
	// in the remote client-side verification middleware.
	if value, ok := a.tokenCache.Get(info.Token); ok {
		claims, ok := value.(*AccessTokenClaims)
		if !ok {
			return nil, fmt.Errorf("%w: failed to assert cache claims", ErrTokenVerification)
		}

		return claims, nil
	}

	// Parse and verify the claims with the public key.
	claims := &AccessTokenClaims{}

	if err := a.issuer.DecodeJWEToken(ctx, info.Token, claims, jose.TokenTypeAccessToken); err != nil {
		return nil, fmt.Errorf("failed to decrypt claims: %w", err)
	}

	// Verify the claims.
	expected := jwt.Expected{
		Audience: jwt.Audience{
			info.Audience,
		},
		Issuer: info.Issuer,
		Time:   time.Now(),
	}

	if err := claims.Claims.ValidateWithLeeway(expected, a.options.TokenVerificationLeeway); err != nil {
		return nil, fmt.Errorf("failed to validate claims: %w", err)
	}

	if err := a.verifyCustomClaims(ctx, info, claims); err != nil {
		return nil, err
	}

	// The cache entry needs a timeout as a federated user may have had their rights
	// recinded and we don't know about it, and long lived tokens e.g. service accounts,
	// could still be valid for months...
	timeout := time.Hour

	if tokenExpiresIn := time.Until(claims.Expiry.Time()); tokenExpiresIn < timeout {
		timeout = tokenExpiresIn
	}

	a.tokenCache.Add(info.Token, claims, timeout)

	return claims, nil
}

func (a *Authenticator) verifyCustomClaims(ctx context.Context, info *VerifyInfo, claims *AccessTokenClaims) error {
	// If the token is for a service account, ensure that account exists and
	// the token is still the correct one e.g. hasn't been reissued.
	if claims.Custom == nil {
		return nil
	}

	if claims.Custom.Type == AccessTokenTypeServiceAccount {
		organization := &unikornv1.Organization{}

		if err := a.client.Get(ctx, client.ObjectKey{Namespace: a.namespace, Name: claims.Custom.OrganizationID}, organization); err != nil {
			return err
		}

		serviceAccount := &unikornv1.ServiceAccount{}

		if err := a.client.Get(ctx, client.ObjectKey{Namespace: organization.Status.Namespace, Name: claims.Claims.Subject}, serviceAccount); err != nil {
			return err
		}

		if info.Token != serviceAccount.Spec.AccessToken {
			return fmt.Errorf("%w: service account token invalid", ErrTokenVerification)
		}
	}

	return nil
}

// InvalidateToken immediately invalidates the token so it's unusable again.
// TODO: this only considers caching in the identity service, it's still usable.
func (a *Authenticator) InvalidateToken(ctx context.Context, token string) {
	a.tokenCache.Remove(token)
}
