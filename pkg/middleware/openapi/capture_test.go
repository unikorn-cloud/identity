/*
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

package openapi

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseCapture(t *testing.T) {

	testWithHandler := func(t *testing.T, handler http.Handler) {
		t.Parallel()
		responserec := ReadFromRecorder{httptest.NewRecorder()}
		request := httptest.NewRequest("GET", "/", nil)
		response := captureResponseForValidation(responserec, request, handler)

		assert.Equal(t, 200, response.code)
		assert.Equal(t, "bar", response.header.Get("Foo"))
		body, err := io.ReadAll(response.body)
		require.NoError(t, err)
		assert.Equal(t, "OK", string(body))
	}

	t.Run("200 OK with Write", func(t *testing.T) {
		OKhandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Foo", "bar")
			w.WriteHeader(200)
			io.WriteString(w, "OK")
		})
		testWithHandler(t, OKhandler)
	})

	t.Run("implicit 200 OK", func(t *testing.T) {
		implicitHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Foo", "bar")
			io.WriteString(w, "OK")
		})
		testWithHandler(t, implicitHandler)
	})

	// Some real world handlers might use io.Copy, which will in turn try to use ReadFrom() to be more efficient.
	// The standard http.ResponseWriter implementation implements ReadFrom; implementing Write is enough for io.Copy to
	// work, though. This just double-checks that if there _is_ an implementation of ReadFrom, it will also work
	// as expected.
	t.Run("io.Copy 200 OK", func(t *testing.T) {
		iocopyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Foo", "bar")
			w.WriteHeader(200)
			body := bytes.NewBuffer([]byte("OK"))
			io.Copy(w, body)
		})
		testWithHandler(t, iocopyHandler)

	})

	t.Run("multiwrite 200 OK", func(t *testing.T) {
		multiwriteHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Foo", "bar")
			w.WriteHeader(200)
			io.WriteString(w, "O")
			io.WriteString(w, "K")
		})
		testWithHandler(t, multiwriteHandler)
	})

}

type ReadFromRecorder struct {
	*httptest.ResponseRecorder
}

// This may end up doing a buffered write, or using src.WriteTo; the point is that it's
// there to be called.
func (w ReadFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	return io.Copy(w.ResponseRecorder, src)
}
