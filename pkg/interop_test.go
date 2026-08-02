package sopsprovider

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// TestSopsCLIInterop checks wire compatibility against the real sops binary in
// both directions. Unit tests cannot stand in for this: they only ever prove
// this package agrees with itself, whereas the whole point of the provider is
// that Flux, ArgoCD and anyone running `sops -d` can read what it writes.
//
// The test skips when sops is not on PATH, so it stays green on a bare CI
// runner while still running for anyone who has the tool installed.
func TestSopsCLIInterop(t *testing.T) {
	sops, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops binary not on PATH; skipping the wire-compatibility check")
	}

	dir := t.TempDir()
	cfg := testConfig(t)
	plain := testSecretYAML(t, map[string]string{
		"username": "admin",
		"password": "hunter2",
	})

	runSops := func(t *testing.T, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(sops, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "SOPS_AGE_KEY="+testIdentity)
		out, err := cmd.Output()
		if err != nil {
			stderr := ""
			if exitErr, ok := err.(*exec.ExitError); ok {
				stderr = string(exitErr.Stderr)
			}
			t.Fatalf("sops %v failed: %v\n%s", args, err, stderr)
		}
		return out
	}

	// The .sops.yaml both sides resolve their rule from.
	if err := os.WriteFile(filepath.Join(dir, ".sops.yaml"), sopsYAML(`^(data|stringData)$`), 0o600); err != nil {
		t.Fatalf("failed to write .sops.yaml: %v", err)
	}

	t.Run("the CLI can decrypt what this package encrypts", func(t *testing.T) {
		encrypted, err := EncryptYAML(plain, cfg)
		if err != nil {
			t.Fatalf("EncryptYAML() error = %v", err)
		}
		path := filepath.Join(dir, "ours.yaml")
		if err := os.WriteFile(path, []byte(encrypted.RawYAML), 0o600); err != nil {
			t.Fatalf("failed to write the encrypted document: %v", err)
		}

		got := runSops(t, "-d", "ours.yaml")
		if !reflect.DeepEqual(parseYAML(t, plain), parseYAML(t, got)) {
			t.Errorf("sops -d returned a different document:\nwant %s\ngot  %s", plain, got)
		}
	})

	t.Run("this package can decrypt what the CLI encrypts", func(t *testing.T) {
		path := filepath.Join(dir, "theirs.yaml")
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			t.Fatalf("failed to write the plain document: %v", err)
		}
		encrypted := runSops(t, "-e", "theirs.yaml")

		if !IsSopsEncrypted(encrypted) {
			t.Fatalf("IsSopsEncrypted() = false for a document sops itself produced:\n%s", encrypted)
		}
		got, err := Decrypt(encrypted, cfg)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if !reflect.DeepEqual(parseYAML(t, plain), parseYAML(t, got)) {
			t.Errorf("Decrypt() returned a different document:\nwant %s\ngot  %s", plain, got)
		}
	})

	t.Run("a CLI-encrypted manifest is left alone when nothing changed", func(t *testing.T) {
		path := filepath.Join(dir, "stable.yaml")
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			t.Fatalf("failed to write the plain document: %v", err)
		}
		encrypted := runSops(t, "-e", "stable.yaml")

		got, err := EncryptWithExisting(plain, encrypted, cfg)
		if err != nil {
			t.Fatalf("EncryptWithExisting() error = %v", err)
		}
		if got.Changed {
			t.Error("Changed = true, want false for an unchanged object")
		}
		if got.RawYAML != string(encrypted) {
			t.Errorf("the CLI-written manifest was rewritten:\nwant %s\ngot  %s", encrypted, got.RawYAML)
		}
	})

	t.Run("the CLI can still decrypt after a partial update", func(t *testing.T) {
		path := filepath.Join(dir, "updated.yaml")
		if err := os.WriteFile(path, plain, 0o600); err != nil {
			t.Fatalf("failed to write the plain document: %v", err)
		}
		encrypted := runSops(t, "-e", "updated.yaml")

		rotated := testSecretYAML(t, map[string]string{
			"username": "admin",
			"password": "correct-horse",
		})
		got, err := EncryptWithExisting(rotated, encrypted, cfg)
		if err != nil {
			t.Fatalf("EncryptWithExisting() error = %v", err)
		}
		if !got.Changed {
			t.Fatal("Changed = false, want true")
		}
		if err := os.WriteFile(path, []byte(got.RawYAML), 0o600); err != nil {
			t.Fatalf("failed to write the updated document: %v", err)
		}

		// The MAC must still verify under the CLI after a partial rewrite.
		decrypted := runSops(t, "-d", "updated.yaml")
		if !reflect.DeepEqual(parseYAML(t, rotated), parseYAML(t, decrypted)) {
			t.Errorf("sops -d returned a different document:\nwant %s\ngot  %s", rotated, decrypted)
		}
	})
}
