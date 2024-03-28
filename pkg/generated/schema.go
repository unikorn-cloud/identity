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
