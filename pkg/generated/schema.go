// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen version v1.12.4 DO NOT EDIT.
package generated

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %s", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %s", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	var res = make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	var resolvePath = PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		var pathToFile = url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
