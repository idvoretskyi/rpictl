// Copyright 2026 Ihor Dvoretskyi
// SPDX-License-Identifier: MIT
package agent

import (
	"fmt"
	"strings"
)

// parseSimpleYAML parses a flat "key: value" YAML file into a map.
// Handles string values and simple string-list values (- item per line).
// Not a full YAML parser — sufficient for /etc/rancher/k3s/config.yaml.
func parseSimpleYAML(content string) map[string]interface{} {
	out := map[string]interface{}{}
	lines := strings.Split(content, "\n")
	var currentKey string
	var currentList []string

	flush := func() {
		if currentKey != "" && len(currentList) > 0 {
			out[currentKey] = currentList
			currentKey = ""
			currentList = nil
		}
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "- ") && currentKey != "" {
			currentList = append(currentList, strings.TrimPrefix(strings.TrimSpace(line), "- "))
			continue
		}
		flush()
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			switch v {
			case "":
				currentKey = k
			case "true":
				out[k] = true
			case "false":
				out[k] = false
			default:
				out[k] = v
			}
		}
	}
	flush()
	return out
}

// marshalSimpleYAML serializes a flat map to YAML suitable for k3s config.yaml.
func marshalSimpleYAML(m map[string]interface{}) string {
	var sb strings.Builder
	sb.WriteString("# Managed by rpictl\n")
	for k, v := range m {
		switch val := v.(type) {
		case bool:
			fmt.Fprintf(&sb, "%s: %v\n", k, val)
		case string:
			fmt.Fprintf(&sb, "%s: %s\n", k, val)
		case []string:
			fmt.Fprintf(&sb, "%s:\n", k)
			for _, item := range val {
				fmt.Fprintf(&sb, "  - %s\n", item)
			}
		case []interface{}:
			fmt.Fprintf(&sb, "%s:\n", k)
			for _, item := range val {
				fmt.Fprintf(&sb, "  - %v\n", item)
			}
		default:
			fmt.Fprintf(&sb, "%s: %v\n", k, val)
		}	}
	return sb.String()
}
