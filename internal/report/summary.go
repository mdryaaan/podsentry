package report

// Summary aggregates pass/fail counts across a batch of pod reports.
type Summary struct {
	Total  int
	Passed int
	Failed int
}

// Summarize computes a Summary over reports, treating any report with
// findings, conflicts or warnings as failed.
func Summarize(reports []PodReport) Summary {
	s := Summary{Total: len(reports)}
	for _, r := range reports {
		if r.HasFailures() {
			s.Failed++
		} else {
			s.Passed++
		}
	}
	return s
}
