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

package testing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
	fakecoordinationv1 "k8s.io/client-go/kubernetes/typed/coordination/v1/fake"
	clientgotesting "k8s.io/client-go/testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	Namespace     = "default"
	RefreshPeriod = time.Second
	KeySecretName = "tls-cert"
)

type FakeCoordinationClientGetter struct{}

func (*FakeCoordinationClientGetter) Client() (coordinationv1.CoordinationV1Interface, error) {
	coordination := &fakecoordinationv1.FakeCoordinationV1{
		Fake: &clientgotesting.Fake{},
	}

	return coordination, nil
}

func GenerateSerial(t *testing.T) *big.Int {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	return serial
}

func RotateCertificate(t *testing.T, client client.Client, serial *big.Int) {
	t.Helper()

	pkey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(pkey)
	require.NoError(t, err)

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "my-signing-key",
		},
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pkey.Public(), pkey)
	require.NoError(t, err)

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	}

	key := pem.EncodeToMemory(keyBlock)

	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}

	cert := pem.EncodeToMemory(certBlock)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: Namespace,
			Name:      KeySecretName,
		},
	}

	mutate := func() error {
		secret.Type = corev1.SecretTypeTLS
		secret.Data = map[string][]byte{
			corev1.TLSCertKey:       cert,
			corev1.TLSPrivateKeyKey: key,
		}

		return nil
	}

	_, err = controllerutil.CreateOrUpdate(context.Background(), client, secret, mutate)
	require.NoError(t, err)
}

func CheckCertificate(t *testing.T, cli client.Client, name string, serial *big.Int) {
	t.Helper()

	var secret corev1.Secret

	require.NoError(t, cli.Get(context.Background(), client.ObjectKey{Namespace: Namespace, Name: name}, &secret))

	require.Contains(t, secret.Data, corev1.TLSCertKey)
	require.Contains(t, secret.Data, corev1.TLSPrivateKeyKey)

	tlsCert, err := tls.X509KeyPair(secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey])
	require.NoError(t, err)
	require.Len(t, tlsCert.Certificate, 1)
	require.NotEmpty(t, tlsCert.Certificate[0])

	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	require.NoError(t, err)
	require.Equal(t, 0, cert.SerialNumber.Cmp(serial))
}

func CheckCertificateNotExist(t *testing.T, cli client.Client, name string) {
	t.Helper()

	var secret corev1.Secret

	require.Error(t, cli.Get(context.Background(), client.ObjectKey{Namespace: Namespace, Name: name}, &secret))
}
