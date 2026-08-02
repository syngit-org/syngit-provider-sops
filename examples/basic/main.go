package main

import (
	"fmt"
	"log"
	"os"

	"filippo.io/age"
	sopsprovider "github.com/syngit-org/syngit-provider-sops/pkg"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// targetPath is the path the manifest would occupy in the git repository. SOPS
// resolves the creation rule against it, so users write their path_regex
// against paths of this shape.
const targetPath = "production/core/v1/secrets/db.yaml"

func main() {
	// A throwaway key pair, standing in for the age identity a cluster would
	// hold in a Kubernetes Secret.
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("failed to generate an age key pair: %v", err)
	}

	// 1. Resolve the creation rule from the repository's .sops.yaml. In
	//    production syngit reads these bytes out of the git worktree.
	rules, err := sopsprovider.LoadCreationRule(sopsYAML(identity.Recipient().String()), targetPath)
	if err != nil {
		log.Fatalf("failed to load the creation rule: %v", err)
	}

	// 2. Read the age identity from the Secret. In production this is the
	//    Secret the RemoteSyncer points at, already fetched from the cluster.
	identities, err := sopsprovider.AgeIdentitiesFromSecret(buildAgeSecret(identity.String()))
	if err != nil {
		log.Fatalf("failed to read the age identity: %v", err)
	}

	cfg := sopsprovider.Config{Rules: rules, Identities: identities}

	// 3. Encrypt the intercepted object.
	encrypted, err := sopsprovider.EncryptYAML(mustYAML(buildSecret("hunter2")), cfg)
	if err != nil {
		log.Fatalf("failed to encrypt the secret: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Object:                    %s/%s\n", encrypted.Namespace, encrypted.Name)
	fmt.Fprintf(os.Stderr, "Encrypted regex:           %s\n", rules.EncryptedRegex())
	fmt.Fprintf(os.Stderr, "Recipients:                %v\n", rules.Recipients())
	fmt.Fprintf(os.Stderr, "Identity visible to syngit: %v\n", encrypted.KubernetesIdentityVisible)
	fmt.Fprintf(os.Stderr, "\nDecrypt this output with:\n  SOPS_AGE_KEY=%s sops -d <file>\n\n", identity.String())

	// The encrypted manifest goes to stdout so the example can be piped
	// straight into the sops CLI.
	fmt.Print(encrypted.RawYAML)

	// 4. Re-run against the manifest just produced, with the object unchanged.
	//    Nothing has moved, so nothing is rewritten and syngit has no commit
	//    to make.
	unchanged, err := sopsprovider.EncryptWithExisting(
		mustYAML(buildSecret("hunter2")), []byte(encrypted.RawYAML), cfg)
	if err != nil {
		log.Fatalf("failed to re-encrypt the secret: %v", err)
	}
	fmt.Fprintf(os.Stderr, "\nUnchanged object -> Changed = %v (identical output: %v)\n",
		unchanged.Changed, unchanged.RawYAML == encrypted.RawYAML)

	// 5. Change one value. Only that value's ciphertext is rewritten; the diff
	//    says which paths moved and which of them are actually encrypted.
	rotated, err := sopsprovider.EncryptWithExisting(
		mustYAML(buildSecret("correct-horse")), []byte(encrypted.RawYAML), cfg)
	if err != nil {
		log.Fatalf("failed to re-encrypt the secret: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Rotated password -> Changed = %v, changed paths = %v, of which encrypted = %v\n",
		rotated.Changed, rotated.Diff.ChangedPaths, rotated.Diff.ChangedEncryptedPaths)
}

// sopsYAML is the .sops.yaml a repository would carry: which paths get
// encrypted, with which keys, and how much of each document is covered.
func sopsYAML(recipient string) []byte {
	return []byte(fmt.Sprintf(`creation_rules:
  - path_regex: .*
    encrypted_regex: '^(data|stringData)$'
    age: %s
`, recipient))
}

// mustYAML renders an object the way syngit hands it to the provider.
func mustYAML(obj interface{}) []byte {
	out, err := yaml.Marshal(obj)
	if err != nil {
		log.Fatalf("failed to marshal the object: %v", err)
	}
	return out
}

// buildAgeSecret mimics the Secret a cluster holds the age identity in,
// following the convention Flux established.
func buildAgeSecret(identity string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "sops-age", Namespace: "syngit"},
		Data:       map[string][]byte{"age.agekey": []byte(identity)},
	}
}

// buildSecret is the object syngit would have intercepted at admission time.
func buildSecret(password string) *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db",
			Namespace: "production",
			Labels:    map[string]string{"app": "db"},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"username": "admin",
			"password": password,
		},
	}
}
