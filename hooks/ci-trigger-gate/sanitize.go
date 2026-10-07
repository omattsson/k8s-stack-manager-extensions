package main

import (
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Branch → image tag
// ---------------------------------------------------------------------------

// sanitizeImageTag converts a git branch name to a Docker image tag.
// It is a copy of SanitizeImageTag in k8s-stack-manager
// (backend/internal/helm/values_generator.go). Keep the two in sync: the
// tag must be the same value that Helm renders for {{.ImageTag}}.
func sanitizeImageTag(branch string) string {
	tag := strings.ToLower(branch)
	tag = strings.NewReplacer(
		"/", "-",
		" ", "-",
		"_", "-",
	).Replace(tag)

	// Remove all characters that are not valid in a Docker tag.
	var cleaned strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			cleaned.WriteRune(r)
		}
	}
	tag = cleaned.String()

	// Remove leading dots and dashes.
	tag = strings.TrimLeft(tag, "-.")

	// Docker tags have a limit of 128 characters.
	if len(tag) > 128 {
		tag = tag[:128]
	}

	if tag == "" {
		tag = "latest"
	}
	return tag
}

// ---------------------------------------------------------------------------
// Skip logic
// ---------------------------------------------------------------------------

var semverRe = regexp.MustCompile(`^v?\d+\.\d+\.\d+`)

// skipReason returns a reason when the gate must not touch the chart.
// It returns "" when the gate must process the chart.
func skipReason(chart ChartRef, branch string) string {
	if chart.BuildPipelineID == "" {
		return "no build_pipeline_id"
	}
	if semverRe.MatchString(branch) {
		// Release images are built by the release flow. Never replace them
		// with an alias.
		return "release version " + branch
	}
	return ""
}
