package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const podYAML = `
apiVersion: v1
kind: Pod
metadata:
  name: %s
spec:
  containers:
    - name: app
      image: busybox
`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return path
}

func TestLoadSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "pod.yaml", sprintfPod("solo"))

	results, issues, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
	if len(results) != 1 || results[0].Pod.Name != "solo" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestLoadDirectoryNonRecursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", sprintfPod("a"))
	writeFile(t, dir, "b.yml", sprintfPod("b"))
	writeFile(t, dir, "nested/c.yaml", sprintfPod("c"))
	writeFile(t, dir, "notes.txt", "irrelevant")

	results, _, err := Load(dir, false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results for non-recursive scan, got %d", len(results))
	}
}

func TestLoadDirectoryRecursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", sprintfPod("a"))
	writeFile(t, dir, "nested/c.yaml", sprintfPod("c"))

	results, _, err := Load(dir, true)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results for recursive scan, got %d", len(results))
	}
}

func TestLoadCollectsIssuesWithoutAborting(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", sprintfPod("good"))
	writeFile(t, dir, "bad.yaml", "kind: Deployment\nmetadata:\n  name: dep\n")

	results, issues, err := Load(dir, false)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 valid pod, got %d", len(results))
	}
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue for the skipped Deployment, got %d", len(issues))
	}
}

func sprintfPod(name string) string {
	return fmt.Sprintf(podYAML, name)
}
