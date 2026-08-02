package sopsprovider

import (
	"reflect"
	"testing"

	"github.com/getsops/sops/v3"
	sopsconfig "github.com/getsops/sops/v3/config"
	yamlstore "github.com/getsops/sops/v3/stores/yaml"
)

func TestDiffBranches(t *testing.T) {
	tests := []struct {
		name          string
		old           string
		new           string
		md            sops.Metadata
		wantChanged   []string
		wantEncrypted []string
	}{
		{
			name: "identical documents",
			old:  "a: 1\nb: two\n",
			new:  "a: 1\nb: two\n",
		},
		{
			name:        "reordered keys are not a change",
			old:         "a: 1\nb: two\n",
			new:         "b: two\na: 1\n",
			wantChanged: nil,
		},
		// The cases below leave md zero, which is SOPS' default of encrypting
		// everything, so every changed path is also an encrypted one. They
		// exercise the shape of the walk; the scope classification is covered
		// by the cases that follow.
		{
			name:          "modified scalar",
			old:           "a: 1\nb: two\n",
			new:           "a: 1\nb: three\n",
			wantChanged:   []string{"b"},
			wantEncrypted: []string{"b"},
		},
		{
			name:          "added key",
			old:           "a: 1\n",
			new:           "a: 1\nb: two\n",
			wantChanged:   []string{"b"},
			wantEncrypted: []string{"b"},
		},
		{
			name:          "removed key",
			old:           "a: 1\nb: two\n",
			new:           "a: 1\n",
			wantChanged:   []string{"b"},
			wantEncrypted: []string{"b"},
		},
		{
			name:          "nested change",
			old:           "spec:\n  replicas: 1\n  image: nginx\n",
			new:           "spec:\n  replicas: 2\n  image: nginx\n",
			wantChanged:   []string{"spec.replicas"},
			wantEncrypted: []string{"spec.replicas"},
		},
		{
			name:          "a removed subtree is reported once",
			old:           "spec:\n  a: 1\n  b: 2\nmeta: x\n",
			new:           "meta: x\n",
			wantChanged:   []string{"spec"},
			wantEncrypted: []string{"spec"},
		},
		{
			name:          "mapping replaced by a scalar",
			old:           "spec:\n  a: 1\n",
			new:           "spec: gone\n",
			wantChanged:   []string{"spec"},
			wantEncrypted: []string{"spec"},
		},
		{
			name:          "sequence element changed",
			old:           "items:\n  - a\n  - b\n",
			new:           "items:\n  - a\n  - c\n",
			wantChanged:   []string{"items[1]"},
			wantEncrypted: []string{"items[1]"},
		},
		{
			name:          "sequence grew",
			old:           "items:\n  - a\n",
			new:           "items:\n  - a\n  - b\n",
			wantChanged:   []string{"items[1]"},
			wantEncrypted: []string{"items[1]"},
		},
		{
			name:          "change inside a sequence of mappings",
			old:           "containers:\n  - name: app\n    image: nginx:1\n",
			new:           "containers:\n  - name: app\n    image: nginx:2\n",
			wantChanged:   []string{"containers[0].image"},
			wantEncrypted: []string{"containers[0].image"},
		},
		{
			name:          "encrypted scope classification",
			old:           "data:\n  password: old\nmetadata:\n  name: db\n",
			new:           "data:\n  password: new\nmetadata:\n  name: renamed\n",
			md:            sops.Metadata{EncryptedRegex: `^(data)$`},
			wantChanged:   []string{"data.password", "metadata.name"},
			wantEncrypted: []string{"data.password"},
		},
		{
			name: "a sequence element inherits its parent's scope",
			old:  "data:\n  - old\nother:\n  - old\n",
			new:  "data:\n  - new\nother:\n  - new\n",
			md:   sops.Metadata{EncryptedRegex: `^(data)$`},
			// SOPS does not extend the path inside a sequence, so the element
			// is classified under "data" and is therefore encrypted.
			wantChanged:   []string{"data[0]", "other[0]"},
			wantEncrypted: []string{"data[0]"},
		},
		{
			name:          "unencrypted suffix",
			old:           "password: old\nnotes_unencrypted: old\n",
			new:           "password: new\nnotes_unencrypted: new\n",
			md:            sops.Metadata{UnencryptedSuffix: "_unencrypted"},
			wantChanged:   []string{"notes_unencrypted", "password"},
			wantEncrypted: []string{"password"},
		},
		{
			name:          "unencrypted regex wins over the default",
			old:           "password: old\npublic: old\n",
			new:           "password: new\npublic: new\n",
			md:            sops.Metadata{UnencryptedRegex: `^public$`},
			wantChanged:   []string{"password", "public"},
			wantEncrypted: []string{"password"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffBranches(parseBranch(t, tt.old), parseBranch(t, tt.new), tt.md)

			if !reflect.DeepEqual(got.ChangedPaths, tt.wantChanged) {
				t.Errorf("ChangedPaths = %v, want %v", got.ChangedPaths, tt.wantChanged)
			}
			if !reflect.DeepEqual(got.ChangedEncryptedPaths, tt.wantEncrypted) {
				t.Errorf("ChangedEncryptedPaths = %v, want %v", got.ChangedEncryptedPaths, tt.wantEncrypted)
			}
			if got.hasChanges() != (len(tt.wantChanged) > 0) {
				t.Errorf("hasChanges() = %v, want %v", got.hasChanges(), len(tt.wantChanged) > 0)
			}
		})
	}
}

func TestDiffNilIsNoChange(t *testing.T) {
	var d *Diff
	if d.hasChanges() {
		t.Error("hasChanges() = true on a nil Diff, want false")
	}
}

// TestShouldEncryptPathMirrorsSops checks the precedence order this package
// reimplements: each setting overrides the previous one, in SOPS' own order.
func TestShouldEncryptPathMirrorsSops(t *testing.T) {
	tests := []struct {
		name string
		md   sops.Metadata
		path []string
		want bool
	}{
		{name: "no settings encrypts everything", path: []string{"data"}, want: true},
		{
			name: "encrypted_regex opts a path in",
			md:   sops.Metadata{EncryptedRegex: `^(data|stringData)$`},
			path: []string{"stringData", "password"},
			want: true,
		},
		{
			name: "encrypted_regex opts everything else out",
			md:   sops.Metadata{EncryptedRegex: `^(data|stringData)$`},
			path: []string{"metadata", "name"},
			want: false,
		},
		{
			name: "any segment matching is enough",
			md:   sops.Metadata{EncryptedRegex: `^data$`},
			path: []string{"spec", "data", "nested", "leaf"},
			want: true,
		},
		{
			name: "encrypted_regex overrides unencrypted_regex",
			md:   sops.Metadata{UnencryptedRegex: `^data$`, EncryptedRegex: `^data$`},
			path: []string{"data"},
			want: true,
		},
		{
			name: "encrypted_suffix opts a path in",
			md:   sops.Metadata{EncryptedSuffix: "_secret"},
			path: []string{"token_secret"},
			want: true,
		},
		{
			name: "encrypted_suffix opts everything else out",
			md:   sops.Metadata{EncryptedSuffix: "_secret"},
			path: []string{"token"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldEncryptPath(tt.md, tt.path); got != tt.want {
				t.Errorf("shouldEncryptPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

// parseBranch loads a cleartext YAML document into the SOPS tree branch the
// diff walks.
func parseBranch(t *testing.T, doc string) sops.TreeBranch {
	t.Helper()
	store := yamlstore.NewStore(&sopsconfig.YAMLStoreConfig{})
	branches, err := store.LoadPlainFile([]byte(doc))
	if err != nil {
		t.Fatalf("failed to parse %q: %v", doc, err)
	}
	if len(branches) != 1 {
		t.Fatalf("expected one document in %q, got %d", doc, len(branches))
	}
	return branches[0]
}
