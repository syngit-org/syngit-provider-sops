package sopsprovider

import (
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
)

// Sopsifies a single-document YAML manifest with the recipients and
// the encryption scope of cfg.Rules. It needs no private key material.
func EncryptYAML(doc []byte, cfg Config) (*EncryptedDocument, error) {
	if cfg.Rules == nil {
		return nil, errors.New("config has no .sops.yaml rules")
	}

	store := newStore(cfg.Indent)
	branch, err := loadPlainDocument(store, doc)
	if err != nil {
		return nil, err
	}

	tree := sops.Tree{
		Branches: sops.TreeBranches{branch},
		Metadata: cfg.Rules.metadata(),
	}

	dataKey, err := generateDataKey(&tree.Metadata)
	if err != nil {
		return nil, err
	}

	return encryptTree(store, &tree, aes.NewCipher(), dataKey, readIdentity(branch), true, nil)
}

// Sopsifies doc while preserving as much of the manifest
// already stored in the repository as it can.
//
// SOPS normally draws a fresh data key and a fresh IV per value on every run,
// so re-encrypting an unchanged object would rewrite the whole file and fill
// the git history with noise. Instead this decrypts the existing manifest,
// compares it against doc, and:
//
//   - returns the existing manifest untouched, with Changed false, when nothing
//     differs;
//   - otherwise re-encrypts with the existing data key through the same cipher
//     the decryption ran on, so unchanged values keep their original ciphertext
//     and only what really changed is rewritten.
//
// It falls back to EncryptYAML when there is no existing manifest, when it is not
// a SOPS document, when it cannot be opened with cfg.Identities, or when it was
// produced under a different set of keys or a different encryption scope than
// cfg.Rules now describes.
func EncryptWithExisting(doc, existing []byte, cfg Config) (*EncryptedDocument, error) {
	if cfg.Rules == nil {
		return nil, errors.New("config has no .sops.yaml rules")
	}
	if len(existing) == 0 || !IsSopsEncrypted(existing) || cfg.Identities == nil {
		return EncryptYAML(doc, cfg)
	}

	store := newStore(cfg.Indent)
	newBranch, err := loadPlainDocument(store, doc)
	if err != nil {
		return nil, err
	}

	existingTree, err := store.LoadEncryptedFile(existing)
	if err != nil {
		// An unreadable manifest is not a reason to fail the sync; replace it.
		return EncryptYAML(doc, cfg)
	}
	if !cfg.Rules.matchesScope(existingTree.Metadata) {
		// The .sops.yaml changed, or a recipient was rotated. Re-key from
		// scratch so the file reflects the current configuration.
		return EncryptYAML(doc, cfg)
	}

	// One cipher for the whole call: it stashes the IV of every value it
	// decrypts, and reuses that IV when the same value is encrypted again.
	// That is what keeps unchanged ciphertext byte-for-byte stable.
	cipher := aes.NewCipher()

	dataKey, err := recoverDataKey(&existingTree.Metadata, cfg.Identities)
	if err != nil {
		return EncryptYAML(doc, cfg)
	}
	if err := decryptTreeValues(&existingTree, cipher, dataKey); err != nil {
		return EncryptYAML(doc, cfg)
	}

	var oldBranch sops.TreeBranch
	if len(existingTree.Branches) > 0 {
		oldBranch = existingTree.Branches[0]
	}

	diff := diffBranches(oldBranch, newBranch, existingTree.Metadata)
	identity := readIdentity(newBranch)
	if !diff.hasChanges() {
		return &EncryptedDocument{
			Namespace:                 identity.namespace,
			Name:                      identity.name,
			RawYAML:                   string(existing),
			Changed:                   false,
			Diff:                      diff,
			KubernetesIdentityVisible: identityVisible(existing, identity),
		}, nil
	}

	// Reuse the existing metadata so the wrapped data keys stay byte-identical;
	// only the values, the MAC and lastmodified are rewritten.
	newTree := sops.Tree{
		Branches: sops.TreeBranches{newBranch},
		Metadata: existingTree.Metadata,
	}
	// The data key must not be carried into the emitted document.
	newTree.Metadata.DataKey = nil

	return encryptTree(store, &newTree, cipher, dataKey, identity, true, diff)
}

// Encrypts the tree in place and renders it. EncryptTree also
// computes the MAC and stamps lastmodified.
func encryptTree(
	store *yamlstore.Store,
	tree *sops.Tree,
	cipher sops.Cipher,
	dataKey []byte,
	identity objectIdentity,
	changed bool,
	diff *Diff,
) (*EncryptedDocument, error) {
	if err := encryptTreeValues(tree, cipher, dataKey); err != nil {
		return nil, err
	}

	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, fmt.Errorf("failed to render the encrypted document: %w", err)
	}

	return &EncryptedDocument{
		Namespace:                 identity.namespace,
		Name:                      identity.name,
		RawYAML:                   string(out),
		Changed:                   changed,
		Diff:                      diff,
		KubernetesIdentityVisible: identityVisible(out, identity),
	}, nil
}
