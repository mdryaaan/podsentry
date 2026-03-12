package pss

import corev1 "k8s.io/api/core/v1"

// Severity classifies how a rule violation should be treated.
type Severity string

const (
	SeverityViolation Severity = "violation"
	SeverityWarning   Severity = "warning"
)

// Finding describes a single rule outcome for a pod or one of its
// containers.
type Finding struct {
	RuleID    string   `json:"ruleId"`
	Level     Level    `json:"level"`
	Container string   `json:"container,omitempty"`
	Severity  Severity `json:"severity"`
	Message   string   `json:"message"`
}

// Rule is a single Pod Security Standard check. Rules operate on the whole
// pod spec so they can inspect both pod-level and container-level fields,
// and report findings per offending container.
type Rule struct {
	ID      string
	Level   Level
	Message string
	Check   func(spec corev1.PodSpec) []Finding
}

func violation(ruleID string, level Level, container, message string) Finding {
	return Finding{RuleID: ruleID, Level: level, Container: container, Severity: SeverityViolation, Message: message}
}
