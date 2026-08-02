package sopsprovider

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/version"
)

// ErrNoCreationRule is returned when no creation_rule in the .sops.yaml matches
// the target path.
var ErrNoCreationRule = errors.New("no .sops.yaml creation rule matches the target path")

// Rules is the resolved SOPS creation rule for one target path: which keys wrap
// the data key, and which parts of the document get encrypted.
//
// It is built from a repository's .sops.yaml by SOPS' own parser, so every
// backend SOPS supports (age, PGP, the KMS providers, key_groups, Shamir) is
// resolved without any work here. The resolved configuration is kept behind an
// unexported field because SOPS only guarantees API stability for its decrypt
// package; callers see the accessors below instead.
type Rules struct {
	cfg  *sopsconfig.Config
	path string
}

// Resolves the creation rule matching targetPath from the
// contents of a .sops.yaml file.
//
// targetPath must be the path as it appears in the repository (for example
// "production/core/v1/secrets/db.yaml"), since that is what users write their
// path_regex against. It returns ErrNoCreationRule when the configuration
// declares no creation rules, or when none of them match.
func LoadCreationRule(sopsYAML []byte, targetPath string) (*Rules, error) {
	if len(sopsYAML) == 0 {
		return nil, errors.New("empty .sops.yaml contents")
	}

	// SOPS only exposes the creation-rule resolver for a config file on disk;
	// its bytes-based parser is unexported. Reimplementing path_regex matching
	// and key-group parsing here would silently drift from SOPS semantics, so
	// the contents are staged in a temporary file instead. A .sops.yaml holds
	// only public key references, so this discloses nothing.
	dir, err := os.MkdirTemp("", "syngit-sops-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(dir) // nolint:errcheck

	confPath := filepath.Join(dir, ".sops.yaml")
	if err := os.WriteFile(confPath, sopsYAML, 0o600); err != nil {
		return nil, fmt.Errorf("failed to stage .sops.yaml: %w", err)
	}

	return LoadCreationRuleFromPath(confPath, targetPath)
}

// LoadCreationRuleFromPath is LoadCreationRule for a .sops.yaml already on disk.
// Note that SOPS resolves targetPath relative to the directory holding confPath.
func LoadCreationRuleFromPath(confPath, targetPath string) (*Rules, error) {
	if targetPath == "" {
		return nil, errors.New("target path must not be empty")
	}

	cfg, err := sopsconfig.LoadCreationRuleForFile(confPath, targetPath, nil)
	if err != nil {
		// SOPS reports "no matching creation rules found" as a plain error;
		// surface it as the sentinel so callers can branch on it.
		if isNoMatchingRule(err) {
			return nil, ErrNoCreationRule
		}
		return nil, fmt.Errorf("failed to load .sops.yaml creation rule: %w", err)
	}
	// A config holding only destination_rules yields (nil, nil).
	if cfg == nil {
		return nil, ErrNoCreationRule
	}
	// SOPS still hands back a single, empty key group for a rule that names no
	// backend at all. Encrypting against it would produce a document nobody
	// could ever open, so reject it here where the cause is still visible.
	if countKeys(cfg.KeyGroups) == 0 {
		return nil, fmt.Errorf("creation rule for %q declares no encryption keys", targetPath)
	}

	return &Rules{cfg: cfg, path: targetPath}, nil
}

// Reports the encrypted_regex of the resolved rule, empty when
// the rule scopes encryption by suffix instead.
func (r *Rules) EncryptedRegex() string {
	if r == nil || r.cfg == nil {
		return ""
	}
	return r.cfg.EncryptedRegex
}

// TargetPath reports the repository path the rule was resolved for.
func (r *Rules) TargetPath() string {
	if r == nil {
		return ""
	}
	return r.path
}

// Recipients renders the master keys of every key group, for logging and for
// comparing one rule against the metadata of an already-encrypted document.
// The rendering is SOPS' own (an age recipient, a PGP fingerprint, a KMS ARN,
// and so on).
func (r *Rules) Recipients() []string {
	if r == nil || r.cfg == nil {
		return nil
	}
	var out []string
	for _, group := range r.cfg.KeyGroups {
		for _, key := range group {
			out = append(out, key.ToString())
		}
	}
	return out
}

// metadata builds the SOPS metadata a freshly encrypted document gets from this
// rule. The returned key groups are the rule's own, so encrypting mutates them
// with the wrapped data key; callers must not reuse a Rules value concurrently.
func (r *Rules) metadata() sops.Metadata {
	return sops.Metadata{
		KeyGroups:               r.cfg.KeyGroups,
		UnencryptedSuffix:       r.cfg.UnencryptedSuffix,
		EncryptedSuffix:         r.cfg.EncryptedSuffix,
		UnencryptedRegex:        r.cfg.UnencryptedRegex,
		EncryptedRegex:          r.cfg.EncryptedRegex,
		UnencryptedCommentRegex: r.cfg.UnencryptedCommentRegex,
		EncryptedCommentRegex:   r.cfg.EncryptedCommentRegex,
		MACOnlyEncrypted:        r.cfg.MACOnlyEncrypted,
		ShamirThreshold:         r.cfg.ShamirThreshold,
		Version:                 version.Version,
	}
}

// Reports whether an existing document's metadata was produced under the same
// encryption scope and the same set of master keys as this rule.
// When it is not, the document has to be re-encrypted from scratch rather than
// updated in place, because its key groups no longer reflect the .sops.yaml.
func (r *Rules) matchesScope(md sops.Metadata) bool {
	if r == nil || r.cfg == nil {
		return false
	}
	if md.UnencryptedSuffix != r.cfg.UnencryptedSuffix ||
		md.EncryptedSuffix != r.cfg.EncryptedSuffix ||
		md.UnencryptedRegex != r.cfg.UnencryptedRegex ||
		md.EncryptedRegex != r.cfg.EncryptedRegex ||
		md.UnencryptedCommentRegex != r.cfg.UnencryptedCommentRegex ||
		md.EncryptedCommentRegex != r.cfg.EncryptedCommentRegex ||
		md.MACOnlyEncrypted != r.cfg.MACOnlyEncrypted ||
		md.ShamirThreshold != r.cfg.ShamirThreshold {
		return false
	}
	return sameKeys(md.KeyGroups, r.cfg.KeyGroups)
}

// countKeys totals the master keys across every group.
func countKeys(groups []sops.KeyGroup) int {
	n := 0
	for _, group := range groups {
		n += len(group)
	}
	return n
}

// Compares two sets of key groups by their rendered master keys, group by
// group and in order. SOPS writes key groups in configuration order,
// so a positional comparison is the right one: a reordered .sops.yaml is a
// deliberate change and warrants a re-encryption.
func sameKeys(a, b []sops.KeyGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j].ToString() != b[i][j].ToString() {
				return false
			}
		}
	}
	return true
}

// Reports whether err is SOPS' "no matching creation rules"
// error. SOPS returns it as a formatted error with no sentinel to match on.
func isNoMatchingRule(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no matching creation rules found")
}
