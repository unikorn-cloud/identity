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
	"m2EcAQA=",
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
