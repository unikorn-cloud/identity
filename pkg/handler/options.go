/*
Copyright 2022-2024 EscherCloud.
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

package handler

import (
	"time"

	"github.com/spf13/pflag"
)

// Options defines configurable handler options.
type Options struct {
	// Host is the hostname of the service, this will be used as the oauth2
	// issuer etc.
	Host string

	// cacheMaxAge defines the max age for cachable items e.g. images and
	// flavors don't change all that often.
	CacheMaxAge time.Duration
}

// AddFlags adds the options flags to the given flag set.
func (o *Options) AddFlags(f *pflag.FlagSet) {
	f.StringVar(&o.Host, "host", "", "The service hostname.")
	f.DurationVar(&o.CacheMaxAge, "cache-max-age", 24*time.Hour, "How long to cache long-lived queries in the browser.")
}
