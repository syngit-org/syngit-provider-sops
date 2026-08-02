package sopsprovider

import (
	"sigs.k8s.io/yaml"
)

// sopsMetadataKey is the top-level key SOPS adds to every document it encrypts.
const sopsMetadataKey = "sops"

// Reports whether the YAML document carries the metadata SOPS writes:
// a top-level "sops" mapping with a version, a MAC, and at least one
// set of master keys. Checking for all three avoids mistaking an unrelated
// "sops" key in a user's manifest for an encrypted document.
func IsSopsEncrypted(doc []byte) bool {
	if len(doc) == 0 {
		return false
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal(doc, &parsed); err != nil {
		return false
	}

	metadata, ok := parsed[sopsMetadataKey].(map[string]interface{})
	if !ok {
		return false
	}
	if _, ok := metadata["version"].(string); !ok {
		return false
	}
	if _, ok := metadata["mac"].(string); !ok {
		return false
	}

	return hasMasterKeys(metadata)
}

// Reports whether the SOPS metadata references at least one master key,
// either through a key group or through one of the flat per-backend
// lists SOPS writes when there is a single group.
func hasMasterKeys(metadata map[string]interface{}) bool {
	if groups, ok := metadata["key_groups"].([]interface{}); ok && len(groups) > 0 {
		return true
	}
	for _, backend := range []string{"age", "pgp", "kms", "gcp_kms", "azure_kv", "hc_vault", "hc_kms"} {
		if entries, ok := metadata[backend].([]interface{}); ok && len(entries) > 0 {
			return true
		}
	}
	return false
}
