package sopsprovider

// Config drives one encryption or decryption call.
type Config struct {
	// Rules is the creation rule resolved from the repository's .sops.yaml.
	// It supplies both the recipients and the encryption scope. Required.
	Rules *Rules

	// Identities supplies the private key material. Only EncryptWithExisting
	// and Decrypt need it; plain encryption works from the recipients alone.
	Identities IdentitySource

	// Indent is the YAML indentation of the emitted document. Zero selects
	// SOPS' own default.
	Indent int
}

// EncryptedDocument is the result of sopsifying one document.
type EncryptedDocument struct {
	// Namespace and Name are read from the document's metadata, and are empty
	// for a document that carries none.
	Namespace string
	Name      string

	// RawYAML is the SOPS-encrypted document, ready to be committed.
	RawYAML string

	// Changed reports whether RawYAML differs from the manifest handed to
	// EncryptWithExisting. It is always true for EncryptYAML.
	Changed bool

	// Diff describes what moved relative to the existing manifest. It is nil
	// unless EncryptWithExisting had an existing manifest it could open.
	Diff *Diff

	// KubernetesIdentityVisible reports whether apiVersion, kind and
	// metadata.name survived in cleartext.
	KubernetesIdentityVisible bool
}

// Diff reports what moved between an existing encrypted manifest and the new
// object, in cleartext terms.
type Diff struct {
	// ChangedPaths lists every dotted path that was added, removed or
	// modified, sorted.
	ChangedPaths []string

	// ChangedEncryptedPaths is the subset of ChangedPaths that falls inside
	// the rule's encrypted scope
	ChangedEncryptedPaths []string
}
