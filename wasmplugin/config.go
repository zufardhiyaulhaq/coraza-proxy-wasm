// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"bytes"
	"fmt"

	"github.com/tidwall/gjson"
)

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
type pluginConfiguration struct {
	globalRules []string
	rulesets    []ruleSet
	identifier  string
}

type ruleSet struct {
	rules     []string
	authority string
}

func parsePluginConfiguration(data []byte) (pluginConfiguration, error) {
	config := pluginConfiguration{}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return config, nil
	}

	if !gjson.ValidBytes(data) {
		return config, fmt.Errorf("invalid json: %q", data)
	}

	jsonData := gjson.ParseBytes(data)
	jsonData.Get("rulesets").ForEach(func(_, value gjson.Result) bool {
		var ruleset ruleSet

		value.Get("rules").ForEach(func(_, value gjson.Result) bool {
			ruleset.rules = append(ruleset.rules, value.String())
			return true
		})

		ruleset.authority = value.Get("authority").String()
		config.rulesets = append(config.rulesets, ruleset)

		return true
	})

	jsonData.Get("globalRules").ForEach(func(_, value gjson.Result) bool {
		config.globalRules = append(config.globalRules, value.String())
		return true
	})

	identifier := jsonData.Get("identifier")
	if identifier.Exists() {
		config.identifier = identifier.String()
	} else {
		config.identifier = "default"
	}

	return config, nil
}
