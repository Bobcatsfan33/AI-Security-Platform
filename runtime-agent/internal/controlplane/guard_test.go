package controlplane

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// banned HTTP forms all use the package-global http.DefaultClient, which has no
// platform-CA pinning and no client certificate. Every agent → control-plane
// call must go through controlplane.NewHTTPClient instead. This test is the
// lint rule that enforces it.
var bannedForms = []string{
	"http.DefaultClient",
	"http.Get(",
	"http.Post(",
	"http.Head(",
	"http.PostForm(",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func TestNoDefaultHTTPClientInAgent(t *testing.T) {
	root := moduleRoot(t)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, form := range bannedForms {
			if bytes.Contains(src, []byte(form)) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("%s uses %q — route control-plane calls through controlplane.NewHTTPClient", rel, form)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
