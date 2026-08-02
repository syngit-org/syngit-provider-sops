package sopsprovider

import (
	"reflect"
	"strings"
	"testing"
)

func TestEncryptYAML(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{
		"username": "admin",
		"password": "hunter2",
	})

	got, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	if got.Namespace != "production" || got.Name != "db" {
		t.Errorf("identity = %s/%s, want production/db", got.Namespace, got.Name)
	}
	if !got.Changed {
		t.Error("Changed = false, want true")
	}
	if got.Diff != nil {
		t.Errorf("Diff = %v, want nil", got.Diff)
	}
	if !got.KubernetesIdentityVisible {
		t.Error("KubernetesIdentityVisible = false, want true")
	}
	if !IsSopsEncrypted([]byte(got.RawYAML)) {
		t.Fatalf("output is not a SOPS document:\n%s", got.RawYAML)
	}

	doc := parseYAML(t, []byte(got.RawYAML))

	// The fields ResourceFinder matches on must survive in cleartext.
	if doc["apiVersion"] != "v1" || doc["kind"] != "Secret" {
		t.Errorf("apiVersion/kind = %v/%v, want v1/Secret", doc["apiVersion"], doc["kind"])
	}
	md, ok := doc["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("metadata is not a mapping: %v", doc["metadata"])
	}
	if md["name"] != "db" || md["namespace"] != "production" {
		t.Errorf("metadata = %v, want name=db namespace=production", md)
	}
	if labels, ok := md["labels"].(map[string]interface{}); !ok || labels["app"] != "db" {
		t.Errorf("labels = %v, want app=db in cleartext", md["labels"])
	}

	// Everything under stringData must be ciphertext.
	for _, key := range []string{"username", "password"} {
		value := stringDataValue(t, doc, key)
		if !strings.HasPrefix(value, "ENC[AES256_GCM,") {
			t.Errorf("stringData.%s = %q, want SOPS ciphertext", key, value)
		}
	}
	if strings.Contains(got.RawYAML, "hunter2") {
		t.Error("the cleartext password leaked into the encrypted document")
	}

	// The recipient from the .sops.yaml must be recorded.
	if !strings.Contains(got.RawYAML, testRecipient) {
		t.Errorf("the encrypted document does not record recipient %s", testRecipient)
	}
}

func TestEncryptYAMLErrors(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})

	tests := []struct {
		name string
		doc  []byte
		cfg  Config
	}{
		{name: "no rules", doc: plain, cfg: Config{}},
		{name: "empty document", doc: nil, cfg: cfg},
		{name: "blank document", doc: []byte("\n\n"), cfg: cfg},
		{
			name: "multi-document input",
			doc:  append(append([]byte{}, plain...), append([]byte("---\n"), plain...)...),
			cfg:  cfg,
		},
		{name: "not YAML", doc: []byte("\tnot: [valid"), cfg: cfg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := EncryptYAML(tt.doc, tt.cfg); err == nil {
				t.Error("EncryptYAML() error = nil, want an error")
			}
		})
	}
}

func TestEncryptYAMLRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{
		"username": "admin",
		"password": "hunter2",
		"tls.crt":  "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	})

	encrypted, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}
	decrypted, err := Decrypt([]byte(encrypted.RawYAML), cfg)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !reflect.DeepEqual(parseYAML(t, plain), parseYAML(t, decrypted)) {
		t.Errorf("round trip changed the document:\nwant %s\ngot  %s", plain, decrypted)
	}
}

// TestEncryptYAMLIdentityHidden pins the failure mode the
// KubernetesIdentityVisible flag exists to surface: a rule broad enough to
// encrypt apiVersion, kind and metadata.name leaves syngit's ResourceFinder
// unable to locate the document on the next sync.
func TestEncryptYAMLIdentityHidden(t *testing.T) {
	cfg := Config{
		Rules:      testRules(t, `.*`),
		Identities: AgeIdentities{testIdentity},
	}
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})

	got, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}
	if got.KubernetesIdentityVisible {
		t.Error("KubernetesIdentityVisible = true, want false for an all-encrypting rule")
	}
}

// TestEncryptYAMLNonKubernetesDocument covers the "or a given yaml" half of the
// provider: a document that is not a Kubernetes object at all.
func TestEncryptYAMLNonKubernetesDocument(t *testing.T) {
	cfg := Config{
		Rules:      testRules(t, `^(password|token)$`),
		Identities: AgeIdentities{testIdentity},
	}
	plain := []byte("host: db.internal\npassword: hunter2\ntoken: abcdef\n")

	got, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}
	if got.Name != "" || got.Namespace != "" {
		t.Errorf("identity = %s/%s, want empty for a plain YAML document", got.Namespace, got.Name)
	}
	if !got.KubernetesIdentityVisible {
		t.Error("KubernetesIdentityVisible = false; a document with no identity has none to lose")
	}

	doc := parseYAML(t, []byte(got.RawYAML))
	if doc["host"] != "db.internal" {
		t.Errorf("host = %v, want it left in cleartext", doc["host"])
	}
	if password, _ := doc["password"].(string); !strings.HasPrefix(password, "ENC[") {
		t.Errorf("password = %v, want ciphertext", doc["password"])
	}
}
