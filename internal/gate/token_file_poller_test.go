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

package gate

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTokenFilePoller_FileAppearsAfterStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	var mu sync.Mutex
	var received []string
	poller := NewTokenFilePoller(path, 20*time.Millisecond, func(jwt string) {
		mu.Lock()
		received = append(received, jwt)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	poller.Start(ctx)

	// File does not exist yet — no callback.
	time.Sleep(60 * time.Millisecond)
	mu.Lock()
	n := len(received)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("expected no callbacks before file exists, got %d", n)
	}

	// Write the file.
	if err := os.WriteFile(path, []byte("jwt-token-1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Wait for callback.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		n = len(received)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	got := append([]string{}, received...)
	mu.Unlock()

	if len(got) == 0 {
		t.Fatal("expected callback after file appears, got none")
	}
	if got[0] != "jwt-token-1" {
		t.Errorf("expected jwt-token-1, got %q", got[0])
	}
}

func TestTokenFilePoller_ContentChangeTriggersCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	if err := os.WriteFile(path, []byte("token-v1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var received []string
	poller := NewTokenFilePoller(path, 20*time.Millisecond, func(jwt string) {
		mu.Lock()
		received = append(received, jwt)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	poller.Start(ctx)

	// Wait for first callback.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Update content.
	if err := os.WriteFile(path, []byte("token-v2\n"), 0600); err != nil {
		t.Fatal(err)
	}

	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	got := append([]string{}, received...)
	mu.Unlock()

	if len(got) < 2 {
		t.Fatalf("expected at least 2 callbacks, got %d: %v", len(got), got)
	}
	if got[0] != "token-v1" {
		t.Errorf("first callback: expected token-v1, got %q", got[0])
	}
	if got[len(got)-1] != "token-v2" {
		t.Errorf("last callback: expected token-v2, got %q", got[len(got)-1])
	}
}

func TestTokenFilePoller_UnchangedContentNoRepeatCallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	if err := os.WriteFile(path, []byte("stable-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	count := 0
	poller := NewTokenFilePoller(path, 20*time.Millisecond, func(_ string) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	poller.Start(ctx)

	// Let it poll several times.
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	got := count
	mu.Unlock()

	if got != 1 {
		t.Errorf("expected exactly 1 callback for unchanged content, got %d", got)
	}
}

func TestTokenFilePoller_FileDisappearsTriggersClear(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	if err := os.WriteFile(path, []byte("my-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var received []string
	poller := NewTokenFilePoller(path, 20*time.Millisecond, func(jwt string) {
		mu.Lock()
		received = append(received, jwt)
		mu.Unlock()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	poller.Start(ctx)

	// Wait for initial callback.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Delete the file.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// Wait for empty-string callback.
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(received)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	got := append([]string{}, received...)
	mu.Unlock()

	if len(got) < 2 {
		t.Fatalf("expected at least 2 callbacks (token + clear), got %d: %v", len(got), got)
	}
	if got[len(got)-1] != "" {
		t.Errorf("expected empty string callback on file disappearance, got %q", got[len(got)-1])
	}
}

func TestTokenFilePoller_ContextCancellationStops(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	var mu sync.Mutex
	count := 0
	poller := NewTokenFilePoller(path, 20*time.Millisecond, func(_ string) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	poller.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Write file after cancellation — should not trigger callback.
	if err := os.WriteFile(path, []byte("late-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	got := count
	mu.Unlock()
	if got != 0 {
		t.Errorf("expected no callbacks after context cancellation, got %d", got)
	}
}
