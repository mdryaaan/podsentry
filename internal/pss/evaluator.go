package pss

import corev1 "k8s.io/api/core/v1"

// Result is the outcome of evaluating a pod against a target Pod Security
// Standard level.
type Result struct {
	TargetLevel Level
	Compliant   bool
	Findings    []Finding
}

// RulesFor returns every rule that applies at or below the given level.
// A pod is only compliant with a target level if it satisfies every rule
// up to and including that level, since each level builds on the ones
// below it.
func RulesFor(level Level) []Rule {
	var rules []Rule
	for _, l := range level.AtMost() {
		switch l {
		case LevelPrivileged:
			rules = append(rules, PrivilegedRules()...)
		case LevelBaseline:
			rules = append(rules, BaselineRules()...)
		case LevelRestricted:
			rules = append(rules, RestrictedRules()...)
		}
	}
	return rules
}

// Evaluate checks spec against every rule required by the target level and
// returns the aggregated result.
func Evaluate(spec corev1.PodSpec, target Level) Result {
	var findings []Finding
	for _, rule := range RulesFor(target) {
		findings = append(findings, rule.Check(spec)...)
	}
	return Result{
		TargetLevel: target,
		Compliant:   len(findings) == 0,
		Findings:    findings,
	}
}

// HighestCompliantLevel returns the most restrictive level the pod fully
// satisfies, evaluated from Restricted down to Privileged.
func HighestCompliantLevel(spec corev1.PodSpec) Level {
	for _, level := range []Level{LevelRestricted, LevelBaseline} {
		if Evaluate(spec, level).Compliant {
			return level
		}
	}
	return LevelPrivileged
}
