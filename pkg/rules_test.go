package sopsprovider

import (
	"errors"
	"reflect"
	"testing"
)

func TestLoadCreationRule(t *testing.T) {
	multiRule := []byte(`creation_rules:
  - path_regex: staging/.*
    encrypted_regex: '^(data)$'
    age: ` + otherRecipient + `
  - path_regex: production/.*
    encrypted_regex: '^(data|stringData)$'
    age: ` + testRecipient + `
  - encrypted_regex: '^(everything)$'
    age: ` + otherRecipient + `
`)

	tests := []struct {
		name           string
		sopsYAML       []byte
		targetPath     string
		wantErr        error
		wantRegex      string
		wantRecipients []string
	}{
		{
			name:           "matches the rule for the target path",
			sopsYAML:       multiRule,
			targetPath:     "production/core/v1/secrets/db.yaml",
			wantRegex:      "^(data|stringData)$",
			wantRecipients: []string{testRecipient},
		},
		{
			name:           "first matching rule wins",
			sopsYAML:       multiRule,
			targetPath:     "staging/core/v1/secrets/db.yaml",
			wantRegex:      "^(data)$",
			wantRecipients: []string{otherRecipient},
		},
		{
			name:           "rule without a path_regex is the catch-all",
			sopsYAML:       multiRule,
			targetPath:     "sandbox/whatever.yaml",
			wantRegex:      "^(everything)$",
			wantRecipients: []string{otherRecipient},
		},
		{
			name:           "key_groups form is supported",
			sopsYAML:       sopsYAML(`^(data)$`, testRecipient, otherRecipient),
			targetPath:     testTargetPath,
			wantRegex:      "^(data)$",
			wantRecipients: []string{testRecipient, otherRecipient},
		},
		{
			name: "no matching rule",
			sopsYAML: []byte(`creation_rules:
  - path_regex: staging/.*
    age: ` + testRecipient + `
`),
			targetPath: "production/db.yaml",
			wantErr:    ErrNoCreationRule,
		},
		{
			name: "config with only destination rules",
			sopsYAML: []byte(`destination_rules:
  - path_regex: .*
    s3_bucket: example
    recreation_rule:
      age: ` + testRecipient + `
`),
			targetPath: testTargetPath,
			wantErr:    ErrNoCreationRule,
		},
		{
			name:       "empty contents",
			sopsYAML:   nil,
			targetPath: testTargetPath,
			wantErr:    errSome,
		},
		{
			name:       "malformed YAML",
			sopsYAML:   []byte("creation_rules: [[[\n"),
			targetPath: testTargetPath,
			wantErr:    errSome,
		},
		{
			name:       "empty target path",
			sopsYAML:   sopsYAML(`^(data)$`),
			targetPath: "",
			wantErr:    errSome,
		},
		{
			name: "rule declaring no keys",
			sopsYAML: []byte(`creation_rules:
  - path_regex: .*
    encrypted_regex: '^(data)$'
`),
			targetPath: testTargetPath,
			wantErr:    errSome,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := LoadCreationRule(tt.sopsYAML, tt.targetPath)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("LoadCreationRule() error = nil, want an error")
				}
				if !errors.Is(tt.wantErr, errSome) && !errors.Is(err, tt.wantErr) {
					t.Fatalf("LoadCreationRule() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadCreationRule() error = %v", err)
			}
			if got := rules.EncryptedRegex(); got != tt.wantRegex {
				t.Errorf("EncryptedRegex() = %q, want %q", got, tt.wantRegex)
			}
			if got := rules.Recipients(); !reflect.DeepEqual(got, tt.wantRecipients) {
				t.Errorf("Recipients() = %v, want %v", got, tt.wantRecipients)
			}
			if got := rules.TargetPath(); got != tt.targetPath {
				t.Errorf("TargetPath() = %q, want %q", got, tt.targetPath)
			}
		})
	}
}

// errSome marks a test case that wants any error, without pinning its identity.
var errSome = errors.New("any error")

func TestRulesNilReceiverIsSafe(t *testing.T) {
	var r *Rules
	if got := r.EncryptedRegex(); got != "" {
		t.Errorf("EncryptedRegex() = %q, want empty", got)
	}
	if got := r.TargetPath(); got != "" {
		t.Errorf("TargetPath() = %q, want empty", got)
	}
	if got := r.Recipients(); got != nil {
		t.Errorf("Recipients() = %v, want nil", got)
	}
	if r.matchesScope(testRules(t, `^(data)$`).metadata()) {
		t.Error("matchesScope() = true on a nil receiver, want false")
	}
}

func TestRulesMatchesScope(t *testing.T) {
	base := testRules(t, `^(data|stringData)$`)

	tests := []struct {
		name  string
		other *Rules
		want  bool
	}{
		{
			name:  "same rule",
			other: testRules(t, `^(data|stringData)$`),
			want:  true,
		},
		{
			name:  "different encrypted_regex",
			other: testRules(t, `^(data)$`),
			want:  false,
		},
		{
			name:  "rotated recipient",
			other: testRules(t, `^(data|stringData)$`, otherRecipient),
			want:  false,
		},
		{
			name:  "additional recipient",
			other: testRules(t, `^(data|stringData)$`, testRecipient, otherRecipient),
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := base.matchesScope(tt.other.metadata()); got != tt.want {
				t.Errorf("matchesScope() = %v, want %v", got, tt.want)
			}
		})
	}
}
