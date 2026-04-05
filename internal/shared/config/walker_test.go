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

package config_test

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"

	cfgloader "github.com/paclabsnet/PortcullisMCP/internal/shared/config"
)

// helpers

func collectWalk(v reflect.Value) (map[string]string, error) {
	result := make(map[string]string)
	err := cfgloader.Walk(v, "", func(path, value string) error {
		result[path] = value
		return nil
	})
	return result, err
}

// --- struct traversal ---

func TestWalk_SimpleStruct(t *testing.T) {
	type S struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	}
	s := S{Name: "alice", Value: "42"}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["name"] != "alice" {
		t.Errorf("name = %q, want %q", got["name"], "alice")
	}
	if got["value"] != "42" {
		t.Errorf("value = %q, want %q", got["value"], "42")
	}
}

func TestWalk_YAMLSkipTag(t *testing.T) {
	type S struct {
		Visible string `yaml:"visible"`
		Hidden  string `yaml:"-"`
	}
	s := S{Visible: "yes", Hidden: "secret"}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["hidden"]; ok {
		t.Error("field tagged yaml:\"-\" should not appear in walk results")
	}
	if _, ok := got["-"]; ok {
		t.Error("field tagged yaml:\"-\" should not appear with key \"-\"")
	}
	if got["visible"] != "yes" {
		t.Errorf("visible = %q, want %q", got["visible"], "yes")
	}
}

func TestWalk_NoYAMLTagFallsBackToFieldName(t *testing.T) {
	type S struct {
		MyField string // no yaml tag
	}
	s := S{MyField: "hello"}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["MyField"] != "hello" {
		t.Errorf("expected key \"MyField\", got map: %v", got)
	}
}

func TestWalk_UnexportedFieldSkipped(t *testing.T) {
	type S struct {
		Exported   string `yaml:"exported"`
		unexported string //nolint:unused
	}
	s := S{Exported: "pub"}
	// We can't set unexported via struct literal in a different package,
	// but we can verify exported is found and the map has exactly one entry.
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 entry (exported only), got %d: %v", len(got), got)
	}
}

func TestWalk_NestedStruct(t *testing.T) {
	type Inner struct {
		Token string `yaml:"token"`
	}
	type Outer struct {
		Auth Inner `yaml:"auth"`
	}
	o := Outer{Auth: Inner{Token: "tok"}}
	got, err := collectWalk(reflect.ValueOf(o))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["auth.token"] != "tok" {
		t.Errorf("auth.token = %q, want %q", got["auth.token"], "tok")
	}
}

func TestWalk_EmptyStringIncluded(t *testing.T) {
	type S struct {
		Name string `yaml:"name"`
	}
	s := S{Name: ""}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["name"]; !ok {
		t.Error("empty string field should still appear in walk results")
	}
	if got["name"] != "" {
		t.Errorf("expected empty string value, got %q", got["name"])
	}
}

// --- pointer traversal ---

func TestWalk_NilPointer(t *testing.T) {
	type S struct {
		Name string `yaml:"name"`
	}
	var ptr *S
	got, err := collectWalk(reflect.ValueOf(ptr))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil pointer should yield no results, got: %v", got)
	}
}

func TestWalk_NonNilPointer(t *testing.T) {
	type S struct {
		Val string `yaml:"val"`
	}
	s := &S{Val: "through-ptr"}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["val"] != "through-ptr" {
		t.Errorf("val = %q, want %q", got["val"], "through-ptr")
	}
}

// --- interface traversal ---

func TestWalk_NilInterface(t *testing.T) {
	var iface interface{}
	got, err := collectWalk(reflect.ValueOf(&iface).Elem())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("nil interface should yield no results, got: %v", got)
	}
}

func TestWalk_InterfaceWrappingString(t *testing.T) {
	// Simulate the kind of interface{} values found in map[string]any config fields.
	var iface interface{} = "wrapped"
	paths := []string{}
	vals := []string{}
	err := cfgloader.Walk(reflect.ValueOf(&iface).Elem(), "field", func(p, v string) error {
		paths = append(paths, p)
		vals = append(vals, v)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(paths) != 1 || paths[0] != "field" || vals[0] != "wrapped" {
		t.Errorf("unexpected walk results: paths=%v vals=%v", paths, vals)
	}
}

// --- map traversal ---

func TestWalk_Map(t *testing.T) {
	m := map[string]string{
		"alpha": "a",
		"beta":  "b",
	}
	got, err := collectWalk(reflect.ValueOf(m))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["alpha"] != "a" {
		t.Errorf("alpha = %q, want %q", got["alpha"], "a")
	}
	if got["beta"] != "b" {
		t.Errorf("beta = %q, want %q", got["beta"], "b")
	}
}

func TestWalk_MapNestedInStruct(t *testing.T) {
	type S struct {
		Labels map[string]string `yaml:"labels"`
	}
	s := S{Labels: map[string]string{"env": "prod", "region": "us-east"}}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["labels.env"] != "prod" {
		t.Errorf("labels.env = %q, want %q", got["labels.env"], "prod")
	}
	if got["labels.region"] != "us-east" {
		t.Errorf("labels.region = %q, want %q", got["labels.region"], "us-east")
	}
}

// --- slice traversal ---

func TestWalk_Slice(t *testing.T) {
	s := []string{"x", "y", "z"}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["[0]"] != "x" {
		t.Errorf("[0] = %q, want %q", got["[0]"], "x")
	}
	if got["[2]"] != "z" {
		t.Errorf("[2] = %q, want %q", got["[2]"], "z")
	}
}

func TestWalk_SliceNestedInStruct(t *testing.T) {
	type S struct {
		Tags []string `yaml:"tags"`
	}
	s := S{Tags: []string{"foo", "bar"}}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["tags[0]"] != "foo" {
		t.Errorf("tags[0] = %q, want %q", got["tags[0]"], "foo")
	}
	if got["tags[1]"] != "bar" {
		t.Errorf("tags[1] = %q, want %q", got["tags[1]"], "bar")
	}
}

func TestWalk_EmptySlice(t *testing.T) {
	s := []string{}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty slice should yield no results, got: %v", got)
	}
}

// --- error propagation ---

func TestWalk_VisitorErrorPropagates(t *testing.T) {
	type S struct {
		A string `yaml:"a"`
		B string `yaml:"b"`
	}
	sentinel := errors.New("stop")
	var visited []string
	err := cfgloader.Walk(reflect.ValueOf(S{A: "1", B: "2"}), "", func(path, _ string) error {
		visited = append(visited, path)
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got: %v", err)
	}
	// Only the first field should have been visited before error propagated.
	if len(visited) != 1 {
		t.Errorf("expected walk to stop after first error; visited: %v", visited)
	}
}

// --- yaml tag with options (e.g. ",omitempty") ---

func TestWalk_YAMLTagWithOptions(t *testing.T) {
	type S struct {
		Name string `yaml:"name,omitempty"`
	}
	s := S{Name: "alice"}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The tag name before the comma should be used as the path key.
	if got["name"] != "alice" {
		t.Errorf("name = %q, want %q", got["name"], "alice")
	}
}

// --- complex nested structure ---

func TestWalk_DeepNesting(t *testing.T) {
	type Creds struct {
		Token string `yaml:"token"`
	}
	type Auth struct {
		Type        string `yaml:"type"`
		Credentials Creds  `yaml:"credentials"`
	}
	type Endpoint struct {
		Listen string `yaml:"listen"`
		Auth   Auth   `yaml:"auth"`
	}
	type Server struct {
		Endpoint Endpoint `yaml:"endpoint"`
	}
	type Config struct {
		Server Server `yaml:"server"`
	}

	cfg := Config{Server: Server{Endpoint: Endpoint{
		Listen: "0.0.0.0:8080",
		Auth:   Auth{Type: "bearer", Credentials: Creds{Token: "s3cr3t"}},
	}}}

	got, err := collectWalk(reflect.ValueOf(cfg))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]string{
		"server.endpoint.listen":              "0.0.0.0:8080",
		"server.endpoint.auth.type":           "bearer",
		"server.endpoint.auth.credentials.token": "s3cr3t",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// --- path building at root level ---

func TestWalk_PathPrefixPropagated(t *testing.T) {
	type S struct {
		X string `yaml:"x"`
	}
	var result map[string]string
	err := cfgloader.Walk(reflect.ValueOf(S{X: "val"}), "prefix", func(path, value string) error {
		if result == nil {
			result = make(map[string]string)
		}
		result[path] = value
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["prefix.x"] != "val" {
		t.Errorf("expected path \"prefix.x\", got map: %v", result)
	}
}

// --- non-string kinds are not visited ---

func TestWalk_IntFieldNotVisited(t *testing.T) {
	type S struct {
		Name string `yaml:"name"`
		Port int    `yaml:"port"`
	}
	s := S{Name: "srv", Port: 8080}
	got, err := collectWalk(reflect.ValueOf(s))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := got["port"]; ok {
		t.Error("integer field should not appear in walk results")
	}
	if len(got) != 1 {
		t.Errorf("expected only 1 result (name), got: %v", got)
	}
}

// --- map with non-string value types ---

func TestWalk_MapWithAnyValues(t *testing.T) {
	// Simulates map[string]any where some values are strings and others are not.
	m := map[string]any{
		"host": "localhost",
		"port": 5432, // non-string; should be silently skipped
	}
	got, err := collectWalk(reflect.ValueOf(m))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["host"] != "localhost" {
		t.Errorf("host = %q, want %q", got["host"], "localhost")
	}
	if _, ok := got["port"]; ok {
		t.Error("integer map value should not appear in walk results")
	}
}

// TestWalk_MapKeysAreSorted_Indirectly verifies that all map keys are visited
// (order is not guaranteed, so we collect and sort).
func TestWalk_AllMapKeysVisited(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2", "c": "3"}
	got, err := collectWalk(reflect.ValueOf(m))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"a", "b", "c"}
	if fmt.Sprint(keys) != fmt.Sprint(want) {
		t.Errorf("visited keys = %v, want %v", keys, want)
	}
}
