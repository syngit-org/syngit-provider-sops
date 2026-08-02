# syngit-provider-sops

An addon to use SOPS functionalities into Syngit.

## Feature

Encrypt a YAML document with [SOPS](https://github.com/getsops/sops), so the manifest Syngit pushes to git is encrypted rather than in cleartext. The output is a plain SOPS document.

The encryption scope and the recipients come from the repository's `.sops.yaml`; the private age key comes from a Kubernetes Secret.

See [examples/basic](examples/basic/main.go) for a runnable version.

### Stable diffs

`EncryptWithExisting` takes the manifest already stored in the repository alongside the intercepted object. It decrypts the existing manifest and compares it against the new object instead:

- nothing changed: the existing manifest is returned untouched, with `Changed` false, and there is nothing to commit;
- something changed: only the values that really moved get new ciphertext; everything else keeps the bytes it already had.

`Diff` reports which paths changed, and which of those fall inside the encrypted scope.

It falls back to a full encryption when there is no existing manifest, when it is not a SOPS document, when the configured identities cannot open it, or when `.sops.yaml` has since changed its keys or its scope.

### Key backends

age is the only backend for *decryption* that is, for the stable-diff path and it sits behind the `IdentitySource` interface, so PGP and the KMS backends can be added without touching the encryption API.

*Encryption* supports everything SOPS does. The recipients are resolved by SOPS' own `.sops.yaml` parser, so age, PGP, AWS/GCP/Azure KMS, Hashicorp Vault, `key_groups` and Shamir splitting all work.

The age key is read from a Secret following the convention Flux established: any data entry whose key ends in `.agekey` holds one or more newline-separated identities.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sops-age
  namespace: syngit
stringData:
  age.agekey: AGE-SECRET-KEY-1...
```
