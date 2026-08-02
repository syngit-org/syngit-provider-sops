package sopsprovider

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/getsops/sops/v3"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/shamir"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
	"sigs.k8s.io/yaml"
)

// The three functions below mirror sops' cmd/sops/common.EncryptTree,
// cmd/sops/common.DecryptTree and Tree.GenerateDataKeyWithKeyServices.
//
// They are reimplemented rather than imported because cmd/sops/common belongs
// to the SOPS command line tool and drags urfave/cli and the S3/GCS publishing
// backends in with it, and because the key service indirection is worse than
// useless here: it converts every master key to its wire form before using it,
// which drops any injected identity and makes decryption fall back to the
// SOPS_AGE_KEY* runtime environment. Wrapping and unwrapping the data key
// against keys.MasterKey directly is exactly what SOPS' own local key service
// server does, one layer down.

// generateDataKey draws a fresh data key and wraps it with every master key of
// every group, splitting it across groups with Shamir when there is more than
// one. The wrapped keys are stored on md's master keys, ready to be emitted.
func generateDataKey(md *sops.Metadata) ([]byte, error) {
	if len(md.KeyGroups) == 0 {
		return nil, errors.New("no key groups to encrypt the data key with")
	}

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, fmt.Errorf("could not generate a random data key: %w", err)
	}

	parts := [][]byte{dataKey}
	if len(md.KeyGroups) > 1 {
		if md.ShamirThreshold == 0 {
			md.ShamirThreshold = len(md.KeyGroups)
		}
		var err error
		parts, err = shamir.Split(dataKey, len(md.KeyGroups), md.ShamirThreshold)
		if err != nil {
			return nil, fmt.Errorf("could not split the data key into shamir parts: %w", err)
		}
	}

	for i, group := range md.KeyGroups {
		if len(group) == 0 {
			return nil, fmt.Errorf("key group %d is empty", i)
		}
		var errs []error
		wrapped := false
		for _, key := range group {
			if err := key.Encrypt(parts[i]); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", key.ToString(), err))
				continue
			}
			wrapped = true
		}
		if !wrapped {
			return nil, fmt.Errorf("could not wrap the data key for key group %d: %w", i, errors.Join(errs...))
		}
	}

	return dataKey, nil
}

// Encrypts every in-scope value of the tree and stamps the
// metadata with a fresh MAC and modification time.
func encryptTreeValues(tree *sops.Tree, cipher sops.Cipher, dataKey []byte) error {
	mac, err := tree.Encrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("failed to encrypt the tree: %w", err)
	}
	tree.Metadata.LastModified = time.Now().UTC()
	tree.Metadata.MessageAuthenticationCode, err = cipher.Encrypt(
		mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to encrypt the MAC: %w", err)
	}
	return nil
}

// Decrypts the tree in place and verifies its MAC. The MAC check is not
// optional here: a mismatch means the file was tampered with or was written
// under different metadata, and silently re-encrypting it would launder the
// damage into the repository.
func decryptTreeValues(tree *sops.Tree, cipher sops.Cipher, dataKey []byte) error {
	computedMAC, err := tree.Decrypt(dataKey, cipher)
	if err != nil {
		return fmt.Errorf("failed to decrypt the tree: %w", err)
	}
	fileMAC, err := cipher.Decrypt(
		tree.Metadata.MessageAuthenticationCode, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to decrypt the MAC: %w", err)
	}
	if fileMAC != computedMAC {
		return fmt.Errorf("MAC mismatch: document has %v, computed %v", fileMAC, computedMAC)
	}
	return nil
}

// Builds the YAML store used to parse and emit documents. A zero
// indent leaves SOPS' own default in place.
func newStore(indent int) *yamlstore.Store {
	return yamlstore.NewStore(&sopsconfig.YAMLStoreConfig{Indent: indent})
}

// Parses a cleartext YAML document into a SOPS tree branch.
// Multi-document input is rejected: syngit intercepts one object at a time, and
// silently encrypting only the first document would lose data.
func loadPlainDocument(store *yamlstore.Store, doc []byte) (sops.TreeBranch, error) {
	if len(doc) == 0 {
		return nil, errors.New("empty document")
	}
	branches, err := store.LoadPlainFile(doc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML document: %w", err)
	}
	switch len(branches) {
	case 0:
		return nil, errors.New("document contains no YAML content")
	case 1:
		return branches[0], nil
	default:
		return nil, fmt.Errorf("document contains %d YAML documents, expected exactly one", len(branches))
	}
}

// objectIdentity holds the fields syngit's ResourceFinder uses to locate a
// document in the repository. Any of them may be empty for a document that is
// not a Kubernetes object.
type objectIdentity struct {
	apiVersion string
	kind       string
	name       string
	namespace  string
}

// Reports whether the document carries enough metadata to be
// located by identity.
func (o objectIdentity) isKubernetesObject() bool {
	return o.apiVersion != "" && o.kind != "" && o.name != ""
}

// Extracts apiVersion, kind and metadata.name/namespace from a
// cleartext branch.
func readIdentity(branch sops.TreeBranch) objectIdentity {
	id := objectIdentity{
		apiVersion: branchString(branch, "apiVersion"),
		kind:       branchString(branch, "kind"),
	}
	if md, ok := branchValue(branch, "metadata").(sops.TreeBranch); ok {
		id.name = branchString(md, "name")
		id.namespace = branchString(md, "namespace")
	}
	return id
}

// branchValue returns the value stored under key at the top level of branch.
func branchValue(branch sops.TreeBranch, key string) interface{} {
	for _, item := range branch {
		if k, ok := item.Key.(string); ok && k == key {
			return item.Value
		}
	}
	return nil
}

// Returns the string value stored under key, or "" when it is
// absent or not a string.
func branchString(branch sops.TreeBranch, key string) string {
	s, _ := branchValue(branch, key).(string)
	return s
}

// Reports whether the emitted document still exposes id's
// apiVersion, kind and metadata.name in cleartext.
//
// Documents that are not Kubernetes objects report true: they have no identity
// to lose, and ResourceFinder would never match them that way.
func identityVisible(emitted []byte, id objectIdentity) bool {
	if !id.isKubernetesObject() {
		return true
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(emitted, &doc); err != nil {
		return false
	}
	if doc["apiVersion"] != id.apiVersion || doc["kind"] != id.kind {
		return false
	}
	md, ok := doc["metadata"].(map[string]interface{})
	if !ok {
		return false
	}
	return md["name"] == id.name
}

// Mirrors the (unexported) rule SOPS applies when walking a tree: a value is
// encrypted when any segment of its path opts it in, and the suffix and regex
// settings are applied in the same order SOPS uses, each one overriding the
// previous. The comment-regex settings are left out because this only ever
// classifies data paths, never comments.
func shouldEncryptPath(md sops.Metadata, path []string) bool {
	encrypted := true
	if md.UnencryptedSuffix != "" {
		for _, p := range path {
			if strings.HasSuffix(p, md.UnencryptedSuffix) {
				encrypted = false
				break
			}
		}
	}
	if md.EncryptedSuffix != "" {
		encrypted = false
		for _, p := range path {
			if strings.HasSuffix(p, md.EncryptedSuffix) {
				encrypted = true
				break
			}
		}
	}
	if md.UnencryptedRegex != "" {
		for _, p := range path {
			if matched, _ := regexp.MatchString(md.UnencryptedRegex, p); matched {
				encrypted = false
				break
			}
		}
	}
	if md.EncryptedRegex != "" {
		encrypted = false
		for _, p := range path {
			if matched, _ := regexp.MatchString(md.EncryptedRegex, p); matched {
				encrypted = true
				break
			}
		}
	}
	return encrypted
}
