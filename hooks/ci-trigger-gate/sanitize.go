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
// Skip logic and input checks
// ---------------------------------------------------------------------------

// semverTagRe matches release version tags such as v1.2.3, 1.2.3-rc.1 or V1.2.3.
var semverTagRe = regexp.MustCompile(`(?i)^v?\d+\.\d+\.\d+([.-].*)?$`)

// defaultProtectedTags is the default of PROTECTED_TAGS.
const defaultProtectedTags = `^(latest|v?\d+\.\d+\.\d+([.-].*)?)$`

// skipReason returns a reason when the gate must not touch the chart.
// It returns "" when the gate must process the chart. The check uses the
// image tag, because the tag is what the registry sees.
func skipReason(chart ChartRef, tag string) string {
	if chart.BuildPipelineID == "" {
		return "no build_pipeline_id"
	}
	if semverTagRe.MatchString(tag) {
		// Release images are built by the release flow. Never replace them
		// with an alias and never build them here.
		return "release version " + tag
	}
	return ""
}

var (
	repoNameRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
	tagNameRe  = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)
	branchRe   = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,250}$`)
)

// maxTagLength is the maximum length of an image tag.
const maxTagLength = 128

// maxMarkerSuffix is the maximum length of ALIAS_MARKER_SUFFIX.
const maxMarkerSuffix = 32

var markerSuffixRe = regexp.MustCompile(`^[._-][a-zA-Z0-9._-]*$`)

// validMarkerSuffix reports whether s can be the alias marker suffix.
func validMarkerSuffix(s string) bool {
	return len(s) <= maxMarkerSuffix && markerSuffixRe.MatchString(s)
}

// validRepo reports whether s is a valid image repository name.
func validRepo(s string) bool { return repoNameRe.MatchString(s) }

// validTag reports whether s is a valid image tag.
func validTag(s string) bool { return tagNameRe.MatchString(s) }

// validBranch reports whether a branch name is safe to send to the pipeline.
// The pipeline gets the branch as a template parameter, so the gate accepts
// only a small set of characters.
func validBranch(s string) bool {
	return branchRe.MatchString(s) &&
		!strings.Contains(s, "..") &&
		!strings.HasPrefix(s, "-") &&
		!strings.HasPrefix(s, "/")
}
