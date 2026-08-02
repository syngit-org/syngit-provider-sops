package sopsprovider

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// Throwaway age key pairs, generated for this test suite alone. They protect
// nothing and never leave it.
const (
	testIdentity  = "AGE-SECRET-KEY-1S603S8GCLQDVC2J8UFFZSLNZHDCWZLR935X040MT4W57GMETLFGS988HEY"
	testRecipient = "age1h8pgp8jac0fhmn7esccs45zqv83cjcs9jv2lczz9ead985nkzu5qf9fg0h"

	otherIdentity  = "AGE-SECRET-KEY-1WW95NEVCPQCCYCGWC3LCQED5Y8Q855ZKMX8ZEPNURQ5VS95TAAYQUD04SK"
	otherRecipient = "age1a3n9cgq8rw5jkr3ygefsaf7uu2z0fc49j7hu7khmk0c2snrc7q2qhywd5d"
)

// testTargetPath is the repository path every test resolves its rule for.
const testTargetPath = "production/core/v1/secrets/db.yaml"

// sopsYAML renders a .sops.yaml with a single creation rule matching
// everything, for the given recipients and encrypted_regex.
func sopsYAML(encryptedRegex string, recipients ...string) []byte {
	if len(recipients) == 0 {
		recipients = []string{testRecipient}
	}
	list := ""
	for _, r := range recipients {
		list += fmt.Sprintf("        - %s\n", r)
	}
	return []byte(fmt.Sprintf(`creation_rules:
  - path_regex: .*
    encrypted_regex: '%s'
    key_groups:
      - age:
%s`, encryptedRegex, list))
}

// testRules resolves a rule from sopsYAML, failing the test on error.
func testRules(t *testing.T, encryptedRegex string, recipients ...string) *Rules {
	t.Helper()
	rules, err := LoadCreationRule(sopsYAML(encryptedRegex, recipients...), testTargetPath)
	if err != nil {
		t.Fatalf("LoadCreationRule() error = %v", err)
	}
	return rules
}

// testConfig is the configuration used by most tests: the default Secret scope,
// with the identity that matches testRecipient.
func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Rules:      testRules(t, `^(data|stringData)$`),
		Identities: AgeIdentities{testIdentity},
	}
}

// testSecret builds a Secret manifest with the given data entries.
func testSecret(data map[string]string) *corev1.Secret {
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "db",
			Namespace: "production",
			Labels:    map[string]string{"app": "db"},
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: data,
	}
	return secret
}

// testSecretYAML renders testSecret as the YAML syngit would intercept.
func testSecretYAML(t *testing.T, data map[string]string) []byte {
	t.Helper()
	doc, err := yaml.Marshal(testSecret(data))
	if err != nil {
		t.Fatalf("failed to marshal test secret: %v", err)
	}
	return doc
}

// parseYAML unmarshals a document into a generic map, failing the test on error.
func parseYAML(t *testing.T, doc []byte) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := yaml.Unmarshal(doc, &out); err != nil {
		t.Fatalf("failed to parse YAML: %v\n%s", err, doc)
	}
	return out
}

// stringDataValue reads stringData.<key> out of a parsed document.
func stringDataValue(t *testing.T, doc map[string]interface{}, key string) string {
	t.Helper()
	sd, ok := doc["stringData"].(map[string]interface{})
	if !ok {
		t.Fatalf("document has no stringData mapping: %v", doc)
	}
	v, ok := sd[key].(string)
	if !ok {
		t.Fatalf("stringData.%s is not a string: %v", key, sd[key])
	}
	return v
}
