// Copyright 2026 Policy-as-Code Laboratories (PAC.Labs)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"fmt"
	"reflect"
	"strings"
)

// Walk traverses v depth-first, calling visitor for each string leaf field.
// path is the dotted YAML-tag path (e.g. "server.endpoints.main.listen").
// Fields tagged yaml:"-" and unexported fields are skipped.
// Map keys of any type are included in the path using their string representation.
// Interface values are dereferenced before traversal.
func Walk(v reflect.Value, path string, visitor func(path, value string) error) error {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return nil
		}
		return Walk(v.Elem(), path, visitor)

	case reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return Walk(v.Elem(), path, visitor)

	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("yaml")
			name, _, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			childPath := name
			if path != "" {
				childPath = path + "." + name
			}
			if err := Walk(v.Field(i), childPath, visitor); err != nil {
				return err
			}
		}

	case reflect.String:
		return visitor(path, v.String())

	case reflect.Map:
		for _, key := range v.MapKeys() {
			keyStr := fmt.Sprintf("%v", key.Interface())
			childPath := keyStr
			if path != "" {
				childPath = path + "." + keyStr
			}
			if err := Walk(v.MapIndex(key), childPath, visitor); err != nil {
				return err
			}
		}

	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			if path == "" {
				childPath = fmt.Sprintf("[%d]", i)
			}
			if err := Walk(v.Index(i), childPath, visitor); err != nil {
				return err
			}
		}
	}
	return nil
}
