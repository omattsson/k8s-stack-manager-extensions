package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Sources of a pipeline template parameter (the "from" field).
const (
	fromInstanceName      = "instance.name"
	fromInstanceNamespace = "instance.namespace"
	fromInstanceBranch    = "instance.branch"
	fromSuite             = "suite"
	fromParameter         = "parameter"
	fromValue             = "value"
)

// paramMapping tells where the value of one pipeline template parameter
// comes from. It is one entry of template_parameters in TEST_PIPELINES.
type paramMapping struct {
	From string `json:"from"`
	// Parameter is the action parameter (from "parameter" only).
	Parameter string `json:"parameter,omitempty"`
	// Value is the constant value (from "value" only).
	Value string `json:"value,omitempty"`
	// Values are the allowed values of the action parameter (from
	// "parameter" only). Without them, a value must match paramValueRe.
	Values []string `json:"values,omitempty"`
	// Required: a missing or empty action parameter gives 400. Otherwise the
	// runner does not send the pipeline parameter, and the pipeline default
	// applies (from "parameter" only).
	Required bool `json:"required,omitempty"`
}

var (
	pipelineParamRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	// actionParamRe is the parameter name rule of k8s-stack-manager.
	actionParamRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	// paramValueRe is the rule of a free action parameter value and of the
	// configured values. A value never starts with '-' or '.'.
	paramValueRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)
)

// maxConstValue is the maximum length of a "value" constant.
const maxConstValue = 256

// defaultTemplateParameters are the parameters of a suite without
// template_parameters.
func defaultTemplateParameters() map[string]paramMapping {
	return map[string]paramMapping{
		"stackName": {From: fromInstanceName},
		"namespace": {From: fromInstanceNamespace},
		"branch":    {From: fromInstanceBranch},
		"suite":     {From: fromSuite},
	}
}

// mappings returns the template parameter mapping of the suite.
func (s suiteConfig) mappings() map[string]paramMapping {
	if s.TemplateParameters == nil {
		return defaultTemplateParameters()
	}
	return s.TemplateParameters
}

// firstParameter returns the first pipeline parameter (by name) whose
// source is from, or "".
func firstParameter(m map[string]paramMapping, from string) string {
	for _, name := range sortedKeys(m) {
		if m[name].From == from {
			return name
		}
	}
	return ""
}

// adoptionMatch returns the template parameter values that identify a build
// of the stack: the stack name, and the namespace when the suite sends it.
// It returns nil when the suite does not send the stack name.
func adoptionMatch(m map[string]paramMapping, inst *InstanceRef) map[string]string {
	name := firstParameter(m, fromInstanceName)
	if name == "" {
		return nil
	}
	match := map[string]string{name: inst.Name}
	if ns := firstParameter(m, fromInstanceNamespace); ns != "" {
		match[ns] = inst.Namespace
	}
	return match
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// validateMappings checks the template_parameters of one suite.
func validateMappings(m map[string]paramMapping) error {
	for _, name := range sortedKeys(m) {
		pm := m[name]
		if !pipelineParamRe.MatchString(name) {
			return fmt.Errorf("template parameter name %q must match %s", name, pipelineParamRe)
		}
		if err := validateMapping(pm); err != nil {
			return fmt.Errorf("template parameter %q: %w", name, err)
		}
	}
	return nil
}

func validateMapping(pm paramMapping) error {
	switch pm.From {
	case fromInstanceName, fromInstanceNamespace, fromInstanceBranch, fromSuite:
		if pm.Parameter != "" || pm.Value != "" || pm.Values != nil || pm.Required {
			return fmt.Errorf("from %q takes no parameter, value, values or required", pm.From)
		}
	case fromParameter:
		if !actionParamRe.MatchString(pm.Parameter) {
			return fmt.Errorf("from %q needs parameter: an action parameter name that matches %s", pm.From, actionParamRe)
		}
		if pm.Value != "" {
			return fmt.Errorf("from %q takes no value", pm.From)
		}
		if pm.Values != nil && len(pm.Values) == 0 {
			return errors.New("values must not be empty; omit it to allow any safe value")
		}
		for _, v := range pm.Values {
			if !paramValueRe.MatchString(v) {
				return fmt.Errorf("value %q must match %s", v, paramValueRe)
			}
		}
	case fromValue:
		if pm.Parameter != "" || pm.Values != nil || pm.Required {
			return fmt.Errorf("from %q takes no parameter, values or required", pm.From)
		}
		if pm.Value == "" || len(pm.Value) > maxConstValue || strings.IndexFunc(pm.Value, unicode.IsControl) >= 0 {
			return fmt.Errorf("from %q needs a value of 1 to %d characters without control characters", pm.From, maxConstValue)
		}
	default:
		return fmt.Errorf("unknown from %q; use %s, %s, %s, %s, %s or %s", pm.From,
			fromInstanceName, fromInstanceNamespace, fromInstanceBranch, fromSuite, fromParameter, fromValue)
	}
	return nil
}

// templateParams builds the template parameters of the queue call. It sends
// only the mapped parameters. It returns a message for the user when an
// action parameter is missing or not valid.
func templateParams(m map[string]paramMapping, inst *InstanceRef, branch, suite string, params map[string]any) (map[string]string, string) {
	out := make(map[string]string, len(m))
	for _, name := range sortedKeys(m) {
		pm := m[name]
		switch pm.From {
		case fromInstanceName:
			out[name] = inst.Name
		case fromInstanceNamespace:
			out[name] = inst.Namespace
		case fromInstanceBranch:
			if branch != "" {
				out[name] = branch
			}
		case fromSuite:
			out[name] = suite
		case fromValue:
			out[name] = pm.Value
		case fromParameter:
			v, ok, msg := actionParamValue(params, pm.Parameter)
			switch {
			case msg != "":
				return nil, msg
			case !ok && pm.Required:
				return nil, fmt.Sprintf("Set the parameter %s", pm.Parameter)
			case !ok:
				continue // the pipeline default applies
			case pm.Values != nil && !slices.Contains(pm.Values, v):
				return nil, fmt.Sprintf("The parameter %s must be one of: %s", pm.Parameter, strings.Join(pm.Values, ", "))
			case pm.Values == nil && !paramValueRe.MatchString(v):
				return nil, fmt.Sprintf("The parameter %s may have only letters, digits, '.', '_' and '-', must not start with '.' or '-', and has 1 to 64 characters", pm.Parameter)
			}
			out[name] = v
		}
	}
	return out, ""
}

// actionParamValue reads an action parameter as a string. It returns false
// for a missing, null or empty value. A JSON string, an integer or a boolean
// is valid. The request must be decoded with UseNumber.
func actionParamValue(params map[string]any, name string) (string, bool, string) {
	bad := fmt.Sprintf("The parameter %s must be a string, an integer or a boolean", name)
	switch v := params[name].(type) {
	case nil:
		return "", false, ""
	case string:
		return v, v != "", ""
	case bool:
		return strconv.FormatBool(v), true, ""
	case json.Number:
		if _, err := strconv.ParseInt(v.String(), 10, 64); err != nil {
			return "", false, bad
		}
		return v.String(), true, ""
	default:
		return "", false, bad
	}
}
