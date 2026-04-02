package loader

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
)

// ParsedDocument represents the outcome of parsing a single YAML document.
type ParsedDocument struct {
	Pod     *corev1.Pod
	Skipped bool
	Reason  string
}

// ParsePods reads every YAML document from r and converts the ones that
// describe a Pod into corev1.Pod values. Documents of another Kind are
// skipped rather than treated as errors, since manifest repositories
// routinely mix Pods with Deployments, ConfigMaps and other objects.
func ParsePods(r io.Reader) ([]ParsedDocument, error) {
	decoder := yaml.NewDecoder(r)

	var docs []ParsedDocument
	for {
		var raw map[string]interface{}
		err := decoder.Decode(&raw)
		// errors.Is rather than ==: a decoder may wrap io.EOF, and a direct
		// comparison would then miss the end of the stream and surface it as a
		// decode failure instead.
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return docs, fmt.Errorf("decoding yaml document: %w", err)
		}
		if raw == nil {
			continue
		}

		doc, err := convertDocument(raw)
		if err != nil {
			return docs, fmt.Errorf("converting yaml document: %w", err)
		}
		docs = append(docs, doc)
	}

	return docs, nil
}

func convertDocument(raw map[string]interface{}) (ParsedDocument, error) {
	kind, _ := raw["kind"].(string)

	if kind == "" {
		if !looksLikePodSpec(raw) {
			return ParsedDocument{Skipped: true, Reason: "missing 'kind' field and no recognizable pod spec"}, nil
		}
		raw["kind"] = "Pod"
		if _, ok := raw["apiVersion"]; !ok {
			raw["apiVersion"] = "v1"
		}
	} else if kind != "Pod" {
		return ParsedDocument{Skipped: true, Reason: fmt.Sprintf("kind %q is not Pod", kind)}, nil
	}

	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return ParsedDocument{}, fmt.Errorf("marshaling document to json: %w", err)
	}

	pod := &corev1.Pod{}
	if err := json.Unmarshal(jsonBytes, pod); err != nil {
		return ParsedDocument{}, fmt.Errorf("unmarshaling pod: %w", err)
	}

	return ParsedDocument{Pod: pod}, nil
}

func looksLikePodSpec(raw map[string]interface{}) bool {
	spec, ok := raw["spec"].(map[string]interface{})
	if !ok {
		return false
	}
	_, hasContainers := spec["containers"]
	return hasContainers
}
