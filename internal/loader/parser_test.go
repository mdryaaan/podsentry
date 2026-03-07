package loader

import (
	"strings"
	"testing"
)

func TestParsePodsSingleDocument(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: nginx
spec:
  containers:
    - name: nginx
      image: nginx:1.27
      securityContext:
        runAsNonRoot: true
`
	docs, err := ParsePods(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("ParsePods returned error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}
	if docs[0].Skipped {
		t.Fatalf("expected document to be parsed, got skipped: %s", docs[0].Reason)
	}
	if docs[0].Pod.Name != "nginx" {
		t.Errorf("expected pod name nginx, got %q", docs[0].Pod.Name)
	}
	if len(docs[0].Pod.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(docs[0].Pod.Spec.Containers))
	}
	sc := docs[0].Pod.Spec.Containers[0].SecurityContext
	if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
		t.Errorf("expected runAsNonRoot true, got %+v", sc)
	}
}

func TestParsePodsSkipsNonPodKind(t *testing.T) {
	yaml := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
`
	docs, err := ParsePods(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("ParsePods returned error: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}
	if !docs[0].Skipped {
		t.Fatalf("expected Deployment document to be skipped")
	}
}

func TestParsePodsMultiDocument(t *testing.T) {
	yaml := `
apiVersion: v1
kind: Pod
metadata:
  name: first
spec:
  containers:
    - name: c1
      image: busybox
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated
---
apiVersion: v1
kind: Pod
metadata:
  name: second
spec:
  containers:
    - name: c2
      image: busybox
`
	docs, err := ParsePods(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("ParsePods returned error: %v", err)
	}
	if len(docs) != 3 {
		t.Fatalf("expected 3 documents, got %d", len(docs))
	}

	podNames := []string{}
	for _, d := range docs {
		if !d.Skipped {
			podNames = append(podNames, d.Pod.Name)
		}
	}
	if len(podNames) != 2 || podNames[0] != "first" || podNames[1] != "second" {
		t.Errorf("unexpected pod names: %v", podNames)
	}
}

func TestParsePodsHandlesMissingKindGracefully(t *testing.T) {
	withoutKind := `
metadata:
  name: bare-pod
spec:
  containers:
    - name: app
      image: busybox
`
	docs, err := ParsePods(strings.NewReader(withoutKind))
	if err != nil {
		t.Fatalf("ParsePods returned error: %v", err)
	}
	if len(docs) != 1 || docs[0].Skipped {
		t.Fatalf("expected bare pod spec to be inferred as Pod, got %+v", docs)
	}
	if docs[0].Pod.Name != "bare-pod" {
		t.Errorf("expected name bare-pod, got %q", docs[0].Pod.Name)
	}

	notAPod := `
metadata:
  name: something-else
data:
  key: value
`
	docs, err = ParsePods(strings.NewReader(notAPod))
	if err != nil {
		t.Fatalf("ParsePods returned error: %v", err)
	}
	if len(docs) != 1 || !docs[0].Skipped {
		t.Fatalf("expected document without kind or containers to be skipped, got %+v", docs)
	}
}
