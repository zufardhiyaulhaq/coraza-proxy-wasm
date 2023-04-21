// Copyright The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package wasmplugin

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePluginConfiguration(t *testing.T) {
	testCases := []struct {
		name         string
		config       string
		expectErr    error
		expectConfig pluginConfiguration
	}{
		{
			name: "empty config",
		},
		{
			name:   "empty json",
			config: "{}",
			expectConfig: pluginConfiguration{
				identifier: "default",
			},
		},
		{
			name:      "bad config",
			config:    "abc",
			expectErr: errors.New("invalid json: \"abc\""),
		},
		{
			name: "inline",
			config: `
			{
				"rulesets": [{
					"rules": [
					  "SecRuleEngine On"
					],
					"authority": "foo"
				  }
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rulesets: []ruleSet{
					{
						rules:     []string{"SecRuleEngine On"},
						authority: "foo",
					},
				},
				identifier: "default",
			},
		},
		{
			name: "global rules",
			config: `
			{
				"rulesets": [{
					"rules": [
					  "SecRuleEngine On"
					],
					"authority": "foo"
				  }
				],
				"globalRules": [
					"SecRuleEngine On"
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rulesets: []ruleSet{
					{
						rules:     []string{"SecRuleEngine On"},
						authority: "foo",
					},
				},
				identifier:  "default",
				globalRules: []string{"SecRuleEngine On"},
			},
		},
		{
			name: "inline many entries",
			config: `
			{
				"rulesets": [{
					"rules": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"authority": "foo"
				  }
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rulesets: []ruleSet{
					{
						rules:     []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
						authority: "foo",
					},
				},
				identifier: "default",
			},
		},
		{
			name: "many ruleset",
			config: `
			{
				"rulesets": [{
					"rules": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"authority": "foo"
				  },
				  {
					"rules": ["SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""],
					"authority": "bar"
				  }
				]
			}
			`,
			expectConfig: pluginConfiguration{
				rulesets: []ruleSet{
					{
						rules:     []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
						authority: "foo",
					},
					{
						rules:     []string{"SecRuleEngine On", "Include @owasp_crs/*.conf\nSecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\""},
						authority: "bar",
					},
				},
				identifier: "default",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg, err := parsePluginConfiguration([]byte(testCase.config))
			assert.Equal(t, testCase.expectErr, err)
			assert.Equal(t, testCase.expectConfig, cfg)
		})
	}
}
