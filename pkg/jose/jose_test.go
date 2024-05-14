/*
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

package jose_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unikorn-cloud/identity/pkg/jose"
	josetesting "github.com/unikorn-cloud/identity/pkg/jose/testing"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type TestClaims struct {
	Foo string `json:"foo"`
}

// TestRotation tests the behaviour of the low level certificate rotation code, ensuring
// our shadown keys are kept in sync with what's provided by cert-manager.
func TestRotation(t *testing.T) {
	t.Parallel()

	client := fake.NewFakeClient()

	serial1 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial1)

	options := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, options)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	// After at least one tick, expect the primary copy to exist, and the secondary not to.
	time.Sleep(josetesting.RefreshPeriod * 2)
	josetesting.CheckCertificate(t, client, issuer.GetPrimaryKeyName(), serial1)
	josetesting.CheckCertificateNotExist(t, client, issuer.GetSecondaryKeyName())

	// After ar at least another tick, expect the state to be the same.
	time.Sleep(josetesting.RefreshPeriod)
	josetesting.CheckCertificate(t, client, issuer.GetPrimaryKeyName(), serial1)
	josetesting.CheckCertificateNotExist(t, client, issuer.GetSecondaryKeyName())

	// Rotate the certificate, and after at least one tick the primary should be updated
	// and the old primary copied to the secondary.
	serial2 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial2)

	time.Sleep(josetesting.RefreshPeriod * 2)
	josetesting.CheckCertificate(t, client, issuer.GetPrimaryKeyName(), serial2)
	josetesting.CheckCertificate(t, client, issuer.GetSecondaryKeyName(), serial1)

	// After ar at least another tick, expect the state to be the same.
	time.Sleep(josetesting.RefreshPeriod)
	josetesting.CheckCertificate(t, client, issuer.GetPrimaryKeyName(), serial2)
	josetesting.CheckCertificate(t, client, issuer.GetSecondaryKeyName(), serial1)

	// And one more time...
	serial3 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial3)

	time.Sleep(josetesting.RefreshPeriod * 2)
	josetesting.CheckCertificate(t, client, issuer.GetPrimaryKeyName(), serial3)
	josetesting.CheckCertificate(t, client, issuer.GetSecondaryKeyName(), serial2)
}

// TestJWTIssue tests that issued JWTs validate across key rotation, and cease working
// when a key is rotated out.
func TestJWTIssue(t *testing.T) {
	t.Parallel()

	client := fake.NewFakeClient()

	serial1 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial1)

	options := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, options)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	// Wait for the primary key to be rotated in.
	time.Sleep(josetesting.RefreshPeriod * 2)

	claims := &TestClaims{
		Foo: "bar",
	}

	// Check the token can be issued, and validates.
	token1, err := issuer.EncodeJWT(ctx, claims)
	require.NoError(t, err)

	var decodedClaims TestClaims

	require.NoError(t, issuer.DecodeJWT(ctx, token1, &decodedClaims))

	// Rotate the key, check the existing token and a new on validate.
	serial2 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial2)

	time.Sleep(josetesting.RefreshPeriod * 2)

	token2, err := issuer.EncodeJWT(ctx, claims)
	require.NoError(t, err)

	require.NoError(t, issuer.DecodeJWT(ctx, token1, &decodedClaims))
	require.NoError(t, issuer.DecodeJWT(ctx, token2, &decodedClaims))

	// Do it again, the first token shouldn't work any more, but the second one should.
	serial3 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial3)

	time.Sleep(josetesting.RefreshPeriod * 2)

	require.Error(t, issuer.DecodeJWT(ctx, token1, &decodedClaims))
	require.NoError(t, issuer.DecodeJWT(ctx, token2, &decodedClaims))
}

// TestJWEIssue tests that issued encrypted JWTs validate across key rotation, and cease working
// when a key is rotated out.
func TestJWEIssue(t *testing.T) {
	t.Parallel()

	client := fake.NewFakeClient()

	serial1 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial1)

	options := &jose.Options{
		IssuerSecretName: josetesting.KeySecretName,
		RotationPeriod:   josetesting.RefreshPeriod,
	}

	issuer := jose.NewJWTIssuer(client, josetesting.Namespace, options)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, issuer.Run(ctx, &josetesting.FakeCoordinationClientGetter{}))

	// Wait for the primary key to be rotated in.
	time.Sleep(josetesting.RefreshPeriod * 2)

	claims := &TestClaims{
		Foo: "bar",
	}

	// Check the token can be issued, and validates.
	token1, err := issuer.EncodeJWEToken(ctx, claims, jose.TokenTypeAccessToken)
	require.NoError(t, err)

	var decodedClaims TestClaims

	require.NoError(t, issuer.DecodeJWEToken(ctx, token1, &decodedClaims, jose.TokenTypeAccessToken))

	// Rotate the key, check the existing token and a new on validate.
	serial2 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial2)

	time.Sleep(josetesting.RefreshPeriod * 2)

	token2, err := issuer.EncodeJWEToken(ctx, claims, jose.TokenTypeAccessToken)
	require.NoError(t, err)

	require.NoError(t, issuer.DecodeJWEToken(ctx, token1, &decodedClaims, jose.TokenTypeAccessToken))
	require.NoError(t, issuer.DecodeJWEToken(ctx, token2, &decodedClaims, jose.TokenTypeAccessToken))

	// Do it again, the first token shouldn't work any more, but the second one should.
	serial3 := josetesting.GenerateSerial(t)
	josetesting.RotateCertificate(t, client, serial3)

	time.Sleep(josetesting.RefreshPeriod * 2)

	require.Error(t, issuer.DecodeJWEToken(ctx, token1, &decodedClaims, jose.TokenTypeAccessToken))
	require.NoError(t, issuer.DecodeJWEToken(ctx, token2, &decodedClaims, jose.TokenTypeAccessToken))
}
