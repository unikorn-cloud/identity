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
	"k/hlZP3+/n8CAAD//7L+R/bwfgAA",
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
