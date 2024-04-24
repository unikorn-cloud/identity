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
	"lQAA",
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
