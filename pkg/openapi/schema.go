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
