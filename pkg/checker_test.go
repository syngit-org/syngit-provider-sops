package sopsprovider

import "testing"

func TestIsSopsEncrypted(t *testing.T) {
	encrypted, err := EncryptYAML(testSecretYAML(t, map[string]string{"password": "hunter2"}), testConfig(t))
	if err != nil {
		t.Fatalf("EncryptYAML() error = %v", err)
	}

	tests := []struct {
		name string
		doc  []byte
		want bool
	}{
		{
			name: "a document SOPS produced",
			doc:  []byte(encrypted.RawYAML),
			want: true,
		},
		{
			name: "key_groups form",
			doc: []byte(`stringData:
    password: ENC[AES256_GCM,data:xx,iv:yy,tag:zz,type:str]
sops:
    version: 3.13.3
    mac: ENC[AES256_GCM,data:aa,iv:bb,tag:cc,type:str]
    key_groups:
        - age:
            - recipient: ` + testRecipient + `
              enc: xxx
`),
			want: true,
		},
		{
			name: "a plain Kubernetes manifest",
			doc:  testSecretYAML(t, map[string]string{"password": "hunter2"}),
			want: false,
		},
		{
			name: "an unrelated top-level sops key",
			doc:  []byte("sops:\n    enabled: true\n"),
			want: false,
		},
		{
			name: "sops metadata with no master keys",
			doc:  []byte("sops:\n    version: 3.13.3\n    mac: ENC[x]\n"),
			want: false,
		},
		{
			name: "sops metadata missing the mac",
			doc: []byte(`sops:
    version: 3.13.3
    age:
        - recipient: ` + testRecipient + `
          enc: xxx
`),
			want: false,
		},
		{name: "empty", doc: nil, want: false},
		{name: "not YAML", doc: []byte("\tnope: [["), want: false},
		{name: "a YAML scalar", doc: []byte("just a string\n"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSopsEncrypted(tt.doc); got != tt.want {
				t.Errorf("IsSopsEncrypted() = %v, want %v", got, tt.want)
			}
		})
	}
}
