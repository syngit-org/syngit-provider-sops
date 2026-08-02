package sopsprovider

import (
	"errors"
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestDecrypt(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})
	encrypted, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	// Decrypt reads everything it needs from the document itself, so the rules
	// are not required.
	got, err := Decrypt([]byte(encrypted.RawYAML), Config{Identities: AgeIdentities{testIdentity}})
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !reflect.DeepEqual(parseYAML(t, plain), parseYAML(t, got)) {
		t.Errorf("Decrypt() = %s, want %s", got, plain)
	}
}

func TestDecryptErrors(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})
	encrypted, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	tests := []struct {
		name    string
		doc     []byte
		cfg     Config
		wantErr error
	}{
		{name: "empty document", doc: nil, cfg: cfg},
		{name: "no identities", doc: []byte(encrypted.RawYAML), cfg: Config{}, wantErr: ErrNoIdentities},
		{
			name: "wrong identity",
			doc:  []byte(encrypted.RawYAML),
			cfg:  Config{Identities: AgeIdentities{otherIdentity}},
		},
		{name: "not a SOPS document", doc: plain, cfg: cfg},
		{name: "not YAML", doc: []byte("\tnope: [["), cfg: cfg},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.doc, tt.cfg)
			if err == nil {
				t.Fatal("Decrypt() error = nil, want an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("Decrypt() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestDecryptRejectsATamperedMAC makes sure a document whose ciphertext was
// edited outside SOPS is refused rather than silently returning wrong values.
func TestDecryptRejectsATamperedMAC(t *testing.T) {
	cfg := testConfig(t)
	encrypted, err := EncryptYAML(testSecretYAML(t, map[string]string{"password": "hunter2"}), cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	doc := parseYAML(t, []byte(encrypted.RawYAML))
	sopsMeta := doc["sops"].(map[string]interface{})
	sopsMeta["mac"] = "ENC[AES256_GCM,data:AAAA,iv:AAAA,tag:AAAA,type:str]"
	tampered, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	if _, err := Decrypt(tampered, cfg); err == nil {
		t.Error("Decrypt() error = nil, want a MAC failure")
	}
}
