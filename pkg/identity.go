package sopsprovider

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/shamir"
	corev1 "k8s.io/api/core/v1"
)

// AgeKeySecretSuffix is the Secret data-key suffix that holds age identities.
// It follows the convention Flux established for its own SOPS decryption
// Secrets, so an existing sops-age Secret works unchanged.
const AgeKeySecretSuffix = ".agekey"

// ErrUnsupportedKey is returned by IdentitySource.Unwrap for a master key the
// source cannot handle. Recovery skips such keys and tries the next one.
var ErrUnsupportedKey = errors.New("master key type not supported by this identity source")

// ErrNoIdentities is returned when an operation that needs private key material
// is called without one.
var ErrNoIdentities = errors.New("no identity source configured")

// IdentitySource supplies the private key material that lets EncryptWithExisting
// and Decrypt open the document already stored in the repository.
//
// age is the only implementation today. PGP and the KMS backends plug in by
// implementing Unwrap; nothing in the encryption path needs to change, because
// encryption only ever needs the public recipients from the .sops.yaml.
type IdentitySource interface {
	// Unwrap recovers the data key (or, under Shamir, one part of it) that the
	// given master key wraps. It returns ErrUnsupportedKey when the master key
	// is of a type this source does not handle.
	Unwrap(key keys.MasterKey) ([]byte, error)
}

// AgeIdentities is a list of Bech32-encoded age private keys
// ("AGE-SECRET-KEY-1...").
type AgeIdentities []string

// Unwrap implements IdentitySource for age master keys.
func (a AgeIdentities) Unwrap(key keys.MasterKey) ([]byte, error) {
	ageKey, ok := key.(*age.MasterKey)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	if len(a) == 0 {
		return nil, ErrNoIdentities
	}

	var parsed age.ParsedIdentities
	if err := parsed.Import(a...); err != nil {
		return nil, fmt.Errorf("failed to parse age identities: %w", err)
	}

	// Decrypt through a copy so the caller's tree is never left holding
	// private key material.
	dup := &age.MasterKey{
		Recipient:    ageKey.Recipient,
		EncryptedKey: ageKey.EncryptedKey,
	}
	parsed.ApplyToMasterKey(dup)

	return dup.Decrypt()
}

// AgeIdentitiesFromSecret reads age identities out of an already-fetched
// Kubernetes Secret. It takes the object rather than a client, so this package
// stays free of any Kubernetes client or RBAC coupling.
//
// Every data entry whose key ends in ".agekey" is read as one or more
// newline-separated identities; blank lines and "#" comments are ignored, which
// is the format `age-keygen` writes. Entries are visited in sorted key order so
// the result is deterministic.
func AgeIdentitiesFromSecret(secret *corev1.Secret) (AgeIdentities, error) {
	if secret == nil {
		return nil, errors.New("secret must not be nil")
	}

	names := make([]string, 0, len(secret.Data))
	for name := range secret.Data {
		if strings.HasSuffix(name, AgeKeySecretSuffix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var identities AgeIdentities
	for _, name := range names {
		for _, line := range strings.Split(string(secret.Data[name]), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			identities = append(identities, line)
		}
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("secret %s/%s holds no %q entry with an age identity",
			secret.Namespace, secret.Name, AgeKeySecretSuffix)
	}

	// Reject unparseable material here rather than at decryption time, where
	// the failure would be indistinguishable from "wrong key".
	var parsed age.ParsedIdentities
	if err := parsed.Import(identities...); err != nil {
		return nil, fmt.Errorf("secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return identities, nil
}

// Unwraps the SOPS data key from md's key groups using src, reassembling
// the Shamir parts when the document uses more than one group.
//
// This deliberately bypasses SOPS' key service. The key service converts each
// master key to its wire form before decrypting, which drops any injected
// identity and makes the local server fall back to the SOPS_AGE_KEY* runtime
// environment.
func recoverDataKey(md *sops.Metadata, src IdentitySource) ([]byte, error) {
	if src == nil {
		return nil, ErrNoIdentities
	}
	if len(md.KeyGroups) == 0 {
		return nil, errors.New("document declares no key groups")
	}

	var parts [][]byte
	var errs []error
	for _, group := range md.KeyGroups {
		part, err := unwrapGroup(group, src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		parts = append(parts, part)
	}

	if len(md.KeyGroups) == 1 {
		if len(parts) != 1 {
			return nil, fmt.Errorf("could not recover the data key: %w", errors.Join(errs...))
		}
		return parts[0], nil
	}

	if len(parts) < md.ShamirThreshold {
		return nil, fmt.Errorf("could not recover the data key: %d of %d key groups opened: %w",
			len(parts), md.ShamirThreshold, errors.Join(errs...))
	}
	dataKey, err := shamir.Combine(parts)
	if err != nil {
		return nil, fmt.Errorf("could not combine shamir parts: %w", err)
	}
	return dataKey, nil
}

// Returns the part held by the first master key in the group that
// the identity source can open.
func unwrapGroup(group sops.KeyGroup, src IdentitySource) ([]byte, error) {
	var errs []error
	for _, key := range group {
		part, err := src.Unwrap(key)
		if err == nil {
			return part, nil
		}
		if !errors.Is(err, ErrUnsupportedKey) {
			errs = append(errs, fmt.Errorf("%s: %w", key.ToString(), err))
		}
	}
	if len(errs) == 0 {
		return nil, ErrUnsupportedKey
	}
	return nil, errors.Join(errs...)
}
