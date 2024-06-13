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

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/unikorn-cloud/core/pkg/authorization/accesstoken"
	"github.com/unikorn-cloud/identity/pkg/openapi"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrFormatError is returned when a secret doesn't meet the specification.
	ErrFormatError = errors.New("secret incorrectly formatted")
)

// Client wraps up the raw OpenAPI client with things to make it useable e.g.
// authorization and TLS.
type Client struct {
	// client is a Kubenetes client.
	client client.Client
	// namespace is the namespace the client is running in.
	namespace string
	// host is the identity host name.
	host string
	// caSecretNamespace tells us where to source the CA secret.
	caSecretNamespace string
	// caSecretName is the root CA secret of the identity endpoint.
	caSecretName string
}

// New creates a new client.
func New(client client.Client, namespace string) *Client {
	return &Client{
		client:    client,
		namespace: namespace,
	}
}

// AddFlags adds the options to the CLI flags.
func (c *Client) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&c.host, "identity-host", "", "Identity endpoint URL.")
	f.StringVar(&c.caSecretNamespace, "identity-ca-secret-namespace", "", "Identity endpoint CA certificate secret namespace.")
	f.StringVar(&c.caSecretName, "identity-ca-secret-name", "", "Identity endpoint CA certificate secret.")
}

// tlsClientConfig abstracts away private TLS CAs or self signed certificates.
func (c *Client) tlsClientConfig(ctx context.Context) (*tls.Config, error) {
	if c.caSecretName == "" {
		//nolint:nilnil
		return nil, nil
	}

	namespace := c.namespace

	if c.caSecretNamespace != "" {
		namespace = c.caSecretNamespace
	}

	secret := &corev1.Secret{}

	if err := c.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: c.caSecretName}, secret); err != nil {
		return nil, err
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf("%w: issuer CA not of type kubernetes.io/tls", ErrFormatError)
	}

	cert, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("%w: issuer CA missing tls.crt", ErrFormatError)
	}

	certPool := x509.NewCertPool()

	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		return nil, fmt.Errorf("%w: failed to load identity CA certificate", ErrFormatError)
	}

	config := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}

	return config, nil
}

// httpClient returns a new http client that will transparently do oauth2 header
// injection and refresh token updates.
func (c *Client) httpClient(ctx context.Context) (*http.Client, error) {
	// Handle non-system CA certificates for the OIDC discovery protocol
	// and oauth2 token refresh. This will return nil if none is specified
	// and default to the system roots.
	tlsClientConfig, err := c.tlsClientConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsClientConfig,
		},
	}

	return client, nil
}

// accessTokenInjector implements OAuth2 bearer token authorization.
func accessTokenInjector(ctx context.Context, req *http.Request) error {
	req.Header.Set("Authorization", "bearer "+accesstoken.FromContext(ctx))

	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(req.Header))

	return nil
}

// Client returns a new OpenAPI client that can be used to access the API.
func (c *Client) Client(ctx context.Context) (*openapi.ClientWithResponses, error) {
	httpClient, err := c.httpClient(ctx)
	if err != nil {
		return nil, err
	}

	client, err := openapi.NewClientWithResponses(c.host, openapi.WithHTTPClient(httpClient), openapi.WithRequestEditorFn(accessTokenInjector))
	if err != nil {
		return nil, err
	}

	return client, nil
}
