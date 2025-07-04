// Package openapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.4.1 DO NOT EDIT.
package openapi

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	externalRef0 "github.com/unikorn-cloud/core/pkg/openapi"
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
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
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
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	for rawPath, rawFunc := range externalRef0.PathToRawSpec(path.Join(path.Dir(pathToFile), "https://raw.githubusercontent.com/unikorn-cloud/core/main/pkg/openapi/common.spec.yaml")) {
		if _, ok := res[rawPath]; ok {
			// it is not possible to compare functions in golang, so always overwrite the old value
		}
		res[rawPath] = rawFunc
	}
	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
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
