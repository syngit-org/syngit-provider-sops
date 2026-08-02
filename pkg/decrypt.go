package sopsprovider

import (
	"errors"
	"fmt"

	"github.com/getsops/sops/v3/aes"
)

// Returns the cleartext YAML of a SOPS-encrypted document.
//
// It needs cfg.Identities; cfg.Rules is not consulted, because everything
// needed to open a document is recorded in the document itself. Only the
// identities have to come from outside.
func Decrypt(encrypted []byte, cfg Config) ([]byte, error) {
	if len(encrypted) == 0 {
		return nil, errors.New("empty document")
	}
	if cfg.Identities == nil {
		return nil, ErrNoIdentities
	}

	store := newStore(cfg.Indent)
	tree, err := store.LoadEncryptedFile(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the encrypted document: %w", err)
	}

	dataKey, err := recoverDataKey(&tree.Metadata, cfg.Identities)
	if err != nil {
		return nil, err
	}
	if err := decryptTreeValues(&tree, aes.NewCipher(), dataKey); err != nil {
		return nil, err
	}

	out, err := store.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("failed to render the decrypted document: %w", err)
	}
	return out, nil
}
