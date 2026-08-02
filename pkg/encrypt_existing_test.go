package sopsprovider

import (
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestEncryptWithExistingNoChurn is the test the whole no-churn design exists
// for: re-encrypting an unchanged object must reproduce the stored manifest
// byte for byte, so syngit never writes a commit for an event that changed
// nothing.
func TestEncryptWithExistingNoChurn(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{
		"username": "admin",
		"password": "hunter2",
	})

	first, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	second, err := EncryptWithExisting(plain, []byte(first.RawYAML), cfg)
	if err != nil {
		t.Fatalf("EncryptWithExisting() error = %v", err)
	}

	if second.Changed {
		t.Error("Changed = true, want false for an unchanged object")
	}
	if second.RawYAML != first.RawYAML {
		t.Errorf("the manifest was rewritten:\nwant %s\ngot  %s", first.RawYAML, second.RawYAML)
	}
	if second.Diff == nil || len(second.Diff.ChangedPaths) != 0 {
		t.Errorf("Diff = %+v, want no changed paths", second.Diff)
	}
	if second.Namespace != "production" || second.Name != "db" {
		t.Errorf("identity = %s/%s, want production/db", second.Namespace, second.Name)
	}
}

// TestEncryptWithExistingPartialChange checks that only the value that actually
// changed is rewritten. The IV of every other value is reused, so its
// ciphertext stays byte-identical and the git diff stays readable.
func TestEncryptWithExistingPartialChange(t *testing.T) {
	cfg := testConfig(t)
	before := testSecretYAML(t, map[string]string{
		"username": "admin",
		"password": "hunter2",
	})
	after := testSecretYAML(t, map[string]string{
		"username": "admin",
		"password": "correct-horse",
	})

	existing, err := EncryptYAML(before, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}
	got, err := EncryptWithExisting(after, []byte(existing.RawYAML), cfg)
	if err != nil {
		t.Fatalf("EncryptWithExisting() error = %v", err)
	}

	if !got.Changed {
		t.Fatal("Changed = false, want true")
	}
	want := []string{"stringData.password"}
	if !reflect.DeepEqual(got.Diff.ChangedPaths, want) {
		t.Errorf("ChangedPaths = %v, want %v", got.Diff.ChangedPaths, want)
	}
	if !reflect.DeepEqual(got.Diff.ChangedEncryptedPaths, want) {
		t.Errorf("ChangedEncryptedPaths = %v, want %v", got.Diff.ChangedEncryptedPaths, want)
	}

	oldDoc := parseYAML(t, []byte(existing.RawYAML))
	newDoc := parseYAML(t, []byte(got.RawYAML))

	if stringDataValue(t, oldDoc, "username") != stringDataValue(t, newDoc, "username") {
		t.Error("the ciphertext of the untouched username was rewritten")
	}
	if stringDataValue(t, oldDoc, "password") == stringDataValue(t, newDoc, "password") {
		t.Error("the ciphertext of the changed password was not rewritten")
	}

	decrypted, err := Decrypt([]byte(got.RawYAML), cfg)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !reflect.DeepEqual(parseYAML(t, after), parseYAML(t, decrypted)) {
		t.Errorf("the result does not decrypt back to the new object:\n%s", decrypted)
	}
}

// TestEncryptWithExistingUnencryptedChange covers a change confined to the
// cleartext part of the document: the diff must report it, but classify it as
// outside the encrypted scope, and no ciphertext may move.
func TestEncryptWithExistingUnencryptedChange(t *testing.T) {
	cfg := testConfig(t)
	data := map[string]string{"username": "admin", "password": "hunter2"}

	before := testSecret(data)
	after := testSecret(data)
	after.Labels["app"] = "database"
	after.Annotations = map[string]string{"owner": "platform"}

	beforeYAML, err := yaml.Marshal(before)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	afterYAML, err := yaml.Marshal(after)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	existing, err := EncryptYAML(beforeYAML, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}
	got, err := EncryptWithExisting(afterYAML, []byte(existing.RawYAML), cfg)
	if err != nil {
		t.Fatalf("EncryptWithExisting() error = %v", err)
	}

	if !got.Changed {
		t.Fatal("Changed = false, want true")
	}
	want := []string{"metadata.annotations", "metadata.labels.app"}
	if !reflect.DeepEqual(got.Diff.ChangedPaths, want) {
		t.Errorf("ChangedPaths = %v, want %v", got.Diff.ChangedPaths, want)
	}
	if len(got.Diff.ChangedEncryptedPaths) != 0 {
		t.Errorf("ChangedEncryptedPaths = %v, want none", got.Diff.ChangedEncryptedPaths)
	}

	oldDoc := parseYAML(t, []byte(existing.RawYAML))
	newDoc := parseYAML(t, []byte(got.RawYAML))
	for _, key := range []string{"username", "password"} {
		if stringDataValue(t, oldDoc, key) != stringDataValue(t, newDoc, key) {
			t.Errorf("the ciphertext of %s moved even though only cleartext changed", key)
		}
	}
}

func TestEncryptWithExistingFallsBackToAFullEncryption(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})

	encrypted, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	rotated := Config{
		// A .sops.yaml that now names a different recipient: the stored
		// manifest no longer reflects the configuration and has to be re-keyed.
		Rules:      testRules(t, `^(data|stringData)$`, otherRecipient),
		Identities: AgeIdentities{testIdentity, otherIdentity},
	}
	rescoped := Config{
		Rules:      testRules(t, `^(data)$`),
		Identities: AgeIdentities{testIdentity},
	}

	tests := []struct {
		name     string
		existing []byte
		cfg      Config
	}{
		{name: "no existing manifest", existing: nil, cfg: cfg},
		{name: "existing manifest is not a SOPS document", existing: plain, cfg: cfg},
		{name: "existing manifest is unparseable", existing: []byte("\tnope"), cfg: cfg},
		{name: "no identities configured", existing: []byte(encrypted.RawYAML), cfg: Config{Rules: cfg.Rules}},
		{
			name:     "identities cannot open the manifest",
			existing: []byte(encrypted.RawYAML),
			cfg:      Config{Rules: cfg.Rules, Identities: AgeIdentities{otherIdentity}},
		},
		{name: "recipient was rotated", existing: []byte(encrypted.RawYAML), cfg: rotated},
		{name: "encryption scope changed", existing: []byte(encrypted.RawYAML), cfg: rescoped},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncryptWithExisting(plain, tt.existing, tt.cfg)
			if err != nil {
				t.Fatalf("EncryptWithExisting() error = %v", err)
			}
			if !got.Changed {
				t.Error("Changed = false, want true for a full re-encryption")
			}
			if got.Diff != nil {
				t.Errorf("Diff = %+v, want nil for a full re-encryption", got.Diff)
			}
			if !IsSopsEncrypted([]byte(got.RawYAML)) {
				t.Errorf("output is not a SOPS document:\n%s", got.RawYAML)
			}
		})
	}
}

// TestEncryptWithExistingRejectsATamperedManifest makes sure a manifest whose
// MAC no longer matches is replaced outright rather than partially reused.
func TestEncryptWithExistingRejectsATamperedManifest(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})

	encrypted, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	doc := parseYAML(t, []byte(encrypted.RawYAML))
	sd := doc["stringData"].(map[string]interface{})
	sd["password"] = "ENC[AES256_GCM,data:AAAA,iv:AAAA,tag:AAAA,type:str]"
	tampered, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	got, err := EncryptWithExisting(plain, tampered, cfg)
	if err != nil {
		t.Fatalf("EncryptWithExisting() error = %v", err)
	}
	if !got.Changed {
		t.Error("Changed = false, want true: a tampered manifest must be replaced")
	}
	decrypted, err := Decrypt([]byte(got.RawYAML), cfg)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !reflect.DeepEqual(parseYAML(t, plain), parseYAML(t, decrypted)) {
		t.Error("the replacement does not decrypt back to the intercepted object")
	}
}

func TestEncryptWithExistingErrors(t *testing.T) {
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{"password": "hunter2"})
	encrypted, err := EncryptYAML(plain, cfg)
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	if _, err := EncryptWithExisting(plain, []byte(encrypted.RawYAML), Config{}); err == nil {
		t.Error("EncryptWithExisting() without rules error = nil, want an error")
	}
	if _, err := EncryptWithExisting(nil, []byte(encrypted.RawYAML), cfg); err == nil {
		t.Error("EncryptWithExisting() with an empty document error = nil, want an error")
	}
}
