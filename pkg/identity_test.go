package sopsprovider

import (
	"errors"
	"reflect"
	"testing"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/pgp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAgeIdentitiesFromSecret(t *testing.T) {
	tests := []struct {
		name    string
		secret  *corev1.Secret
		want    AgeIdentities
		wantErr bool
	}{
		{
			name:   "single identity under the flux convention key",
			secret: ageSecret(map[string]string{"age.agekey": testIdentity}),
			want:   AgeIdentities{testIdentity},
		},
		{
			name: "several newline-separated identities",
			secret: ageSecret(map[string]string{
				"age.agekey": testIdentity + "\n" + otherIdentity,
			}),
			want: AgeIdentities{testIdentity, otherIdentity},
		},
		{
			name: "comments and blank lines are ignored",
			secret: ageSecret(map[string]string{
				"age.agekey": "# created: 2026-08-02\n# public key: " + testRecipient + "\n\n" + testIdentity + "\n",
			}),
			want: AgeIdentities{testIdentity},
		},
		{
			name: "several .agekey entries, visited in sorted order",
			secret: ageSecret(map[string]string{
				"b.agekey": otherIdentity,
				"a.agekey": testIdentity,
			}),
			want: AgeIdentities{testIdentity, otherIdentity},
		},
		{
			name: "entries not ending in .agekey are ignored",
			secret: ageSecret(map[string]string{
				"age.agekey":    testIdentity,
				"age.agepubkey": testRecipient,
			}),
			want: AgeIdentities{testIdentity},
		},
		{
			name:    "no recognised entry",
			secret:  ageSecret(map[string]string{"password": "hunter2"}),
			wantErr: true,
		},
		{
			name:    "entry holds only comments",
			secret:  ageSecret(map[string]string{"age.agekey": "# nothing here\n"}),
			wantErr: true,
		},
		{
			name:    "unparseable identity is rejected up front",
			secret:  ageSecret(map[string]string{"age.agekey": "not-an-age-key"}),
			wantErr: true,
		},
		{
			name:    "nil secret",
			secret:  nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AgeIdentitiesFromSecret(tt.secret)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("AgeIdentitiesFromSecret() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("AgeIdentitiesFromSecret() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AgeIdentitiesFromSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAgeIdentitiesUnwrapRejectsForeignKeyTypes(t *testing.T) {
	identities := AgeIdentities{testIdentity}

	_, err := identities.Unwrap(pgp.NewMasterKeyFromFingerprint("DEADBEEF"))
	if !errors.Is(err, ErrUnsupportedKey) {
		t.Errorf("Unwrap(pgp key) error = %v, want ErrUnsupportedKey", err)
	}

	ageKey, err := age.MasterKeyFromRecipient(testRecipient)
	if err != nil {
		t.Fatalf("MasterKeyFromRecipient() error = %v", err)
	}
	if _, err := AgeIdentities(nil).Unwrap(ageKey); !errors.Is(err, ErrNoIdentities) {
		t.Errorf("Unwrap() with no identities error = %v, want ErrNoIdentities", err)
	}
}

func TestAgeIdentitiesUnwrapLeavesTheKeyClean(t *testing.T) {
	ageKey, err := age.MasterKeyFromRecipient(testRecipient)
	if err != nil {
		t.Fatalf("MasterKeyFromRecipient() error = %v", err)
	}
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	if err := ageKey.Encrypt(dataKey); err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	got, err := AgeIdentities{testIdentity}.Unwrap(ageKey)
	if err != nil {
		t.Fatalf("Unwrap() error = %v", err)
	}
	if !reflect.DeepEqual(got, dataKey) {
		t.Errorf("Unwrap() = %q, want %q", got, dataKey)
	}
	// The private material must not have been left behind on the caller's key.
	if ageKey.Identity != "" {
		t.Errorf("Unwrap() left an identity on the master key: %q", ageKey.Identity)
	}
}

func TestRecoverDataKey(t *testing.T) {
	dataKey := []byte("0123456789abcdef0123456789abcdef")

	wrapped := func(t *testing.T, recipient string) sops.KeyGroup {
		t.Helper()
		key, err := age.MasterKeyFromRecipient(recipient)
		if err != nil {
			t.Fatalf("MasterKeyFromRecipient() error = %v", err)
		}
		if err := key.Encrypt(dataKey); err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		return sops.KeyGroup{key}
	}

	t.Run("single group", func(t *testing.T) {
		md := &sops.Metadata{KeyGroups: []sops.KeyGroup{wrapped(t, testRecipient)}}
		got, err := recoverDataKey(md, AgeIdentities{testIdentity})
		if err != nil {
			t.Fatalf("recoverDataKey() error = %v", err)
		}
		if !reflect.DeepEqual(got, dataKey) {
			t.Errorf("recoverDataKey() = %q, want %q", got, dataKey)
		}
	})

	t.Run("wrong identity", func(t *testing.T) {
		md := &sops.Metadata{KeyGroups: []sops.KeyGroup{wrapped(t, testRecipient)}}
		if _, err := recoverDataKey(md, AgeIdentities{otherIdentity}); err == nil {
			t.Error("recoverDataKey() error = nil, want an error")
		}
	})

	t.Run("no identity source", func(t *testing.T) {
		md := &sops.Metadata{KeyGroups: []sops.KeyGroup{wrapped(t, testRecipient)}}
		if _, err := recoverDataKey(md, nil); !errors.Is(err, ErrNoIdentities) {
			t.Errorf("recoverDataKey() error = %v, want ErrNoIdentities", err)
		}
	})

	t.Run("no key groups", func(t *testing.T) {
		if _, err := recoverDataKey(&sops.Metadata{}, AgeIdentities{testIdentity}); err == nil {
			t.Error("recoverDataKey() error = nil, want an error")
		}
	})
}

// TestShamirRoundTrip covers the multi-key-group path end to end: generating a
// split data key and putting it back together through the identity source.
func TestShamirRoundTrip(t *testing.T) {
	first, err := age.MasterKeyFromRecipient(testRecipient)
	if err != nil {
		t.Fatalf("MasterKeyFromRecipient() error = %v", err)
	}
	second, err := age.MasterKeyFromRecipient(otherRecipient)
	if err != nil {
		t.Fatalf("MasterKeyFromRecipient() error = %v", err)
	}

	md := &sops.Metadata{
		KeyGroups:       []sops.KeyGroup{{first}, {second}},
		ShamirThreshold: 2,
	}
	dataKey, err := generateDataKey(md)
	if err != nil {
		t.Fatalf("generateDataKey() error = %v", err)
	}

	got, err := recoverDataKey(md, AgeIdentities{testIdentity, otherIdentity})
	if err != nil {
		t.Fatalf("recoverDataKey() error = %v", err)
	}
	if !reflect.DeepEqual(got, dataKey) {
		t.Errorf("recoverDataKey() = %x, want %x", got, dataKey)
	}

	// One identity is one group, which is below the threshold of two.
	if _, err := recoverDataKey(md, AgeIdentities{testIdentity}); err == nil {
		t.Error("recoverDataKey() with one of two groups error = nil, want an error")
	}
}

func ageSecret(data map[string]string) *corev1.Secret {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "sops-age", Namespace: "syngit"},
		Data:       map[string][]byte{},
	}
	for k, v := range data {
		secret.Data[k] = []byte(v)
	}
	return secret
}
