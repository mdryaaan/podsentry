// Package loader reads Kubernetes Pod manifests from disk and parses them
// into typed corev1.Pod values, without requiring a live cluster.
package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// Result is a single Pod successfully loaded from a manifest file.
type Result struct {
	Path string
	Pod  *corev1.Pod
}

// LoadIssue describes a file or document that could not be turned into a
// Pod. Issues are collected rather than aborting a scan so that one bad
// file in a large manifest repository does not block the rest.
type LoadIssue struct {
	Path   string
	Reason string
}

func (i LoadIssue) String() string {
	return fmt.Sprintf("%s: %s", i.Path, i.Reason)
}

var yamlExtensions = map[string]bool{
	".yaml": true,
	".yml":  true,
}

// Load reads Pods from path, which may be a single file or a directory.
// When path is a directory, recursive controls whether subdirectories are
// scanned as well.
func Load(path string, recursive bool) ([]Result, []LoadIssue, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading path %q: %w", path, err)
	}

	if !info.IsDir() {
		results, issues := loadFile(path)
		return results, issues, nil
	}

	files, err := collectYAMLFiles(path, recursive)
	if err != nil {
		return nil, nil, fmt.Errorf("walking directory %q: %w", path, err)
	}

	var results []Result
	var issues []LoadIssue
	for _, file := range files {
		fileResults, fileIssues := loadFile(file)
		results = append(results, fileResults...)
		issues = append(issues, fileIssues...)
	}

	return results, issues, nil
}

func loadFile(path string) ([]Result, []LoadIssue) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []LoadIssue{{Path: path, Reason: fmt.Sprintf("opening file: %v", err)}}
	}
	defer f.Close()

	docs, err := ParsePods(f)
	if err != nil {
		return nil, []LoadIssue{{Path: path, Reason: err.Error()}}
	}

	var results []Result
	var issues []LoadIssue
	for _, doc := range docs {
		if doc.Skipped {
			issues = append(issues, LoadIssue{Path: path, Reason: doc.Reason})
			continue
		}
		results = append(results, Result{Path: path, Pod: doc.Pod})
	}

	return results, issues
}

func collectYAMLFiles(root string, recursive bool) ([]string, error) {
	var files []string

	if !recursive {
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if yamlExtensions[strings.ToLower(filepath.Ext(entry.Name()))] {
				files = append(files, filepath.Join(root, entry.Name()))
			}
		}
		sort.Strings(files)
		return files, nil
	}

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if yamlExtensions[strings.ToLower(filepath.Ext(d.Name()))] {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}
