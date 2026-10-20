package hack_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestToolCacheTracksModulePins(t *testing.T) {
	for _, manifest := range []string{"go.mod", "go.sum"} {
		for _, entry := range []string{"root", "tools"} {
			t.Run(entry+"/"+manifest, func(t *testing.T) {
				dir := t.TempDir()
				source, err := os.OpenRoot("..")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = source.Close() })
				fixture, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = fixture.Close() })
				if err := fixture.MkdirAll("tools/bin", 0700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"Makefile", "tools/Makefile", "tools/go.mod", "tools/go.sum"} {
					data, err := source.ReadFile(name)
					if err != nil {
						t.Fatal(err)
					}
					if err := fixture.WriteFile(name, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				old := time.Unix(1_000_000, 0)
				for _, name := range []string{"gosec", "staticcheck", "govulncheck"} {
					path := filepath.Join("tools", "bin", name)
					if err := fixture.WriteFile(path, nil, 0600); err != nil {
						t.Fatal(err)
					}
					if err := fixture.Chtimes(path, old, old); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{"go.mod", "go.sum"} {
					stamp := old.Add(-time.Hour)
					if name == manifest {
						stamp = old.Add(time.Hour)
					}
					if err := fixture.Chtimes(filepath.Join("tools", name), stamp, stamp); err != nil {
						t.Fatal(err)
					}
				}
				target := "tools/bin/staticcheck"
				cwd := dir
				if entry == "tools" {
					cwd = filepath.Join(dir, "tools")
					target = "all"
				}
				cmd := exec.Command("make", "-n", target, "VERSION=test")
				cmd.Dir = cwd
				out, err := cmd.CombinedOutput()
				if err != nil || !strings.Contains(string(out), "go install honnef.co/go/tools/cmd/staticcheck") {
					t.Fatalf("changed %s must invalidate cached tools: err=%v, output=%s", manifest, err, out)
				}
			})
		}
	}
}
