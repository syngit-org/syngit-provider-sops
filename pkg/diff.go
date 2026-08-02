package sopsprovider

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/getsops/sops/v3"
)

// change is one difference between two cleartext trees.
type change struct {
	// keys are the mapping keys leading to the value, and only those. SOPS
	// does not extend a path when it walks into a sequence, so a list element
	// is classified under its parent key.
	keys []string
	// display is the human-readable path, list indices included.
	display string
}

// Compares two cleartext SOPS branches and reports every dotted
// path that was added, removed or modified, split into all changes and the
// subset that falls inside md's encrypted scope.
//
// Comments are ignored: SOPS encrypts them, but a comment change is not a
// change to the object syngit intercepted.
func diffBranches(oldBranch, newBranch sops.TreeBranch, md sops.Metadata) *Diff {
	var changes []change
	walkDiff(oldBranch, newBranch, nil, nil, &changes)

	sort.Slice(changes, func(i, j int) bool { return changes[i].display < changes[j].display })

	d := &Diff{}
	for _, c := range changes {
		d.ChangedPaths = append(d.ChangedPaths, c.display)
		if shouldEncryptPath(md, c.keys) {
			d.ChangedEncryptedPaths = append(d.ChangedEncryptedPaths, c.display)
		}
	}
	return d
}

// hasChanges reports whether the diff found anything at all.
func (d *Diff) hasChanges() bool {
	return d != nil && len(d.ChangedPaths) > 0
}

// Recursively compares two values, appending every difference to out.
// A key present on only one side is reported at its own path rather than
// descended into, so a whole removed subtree is a single entry.
func walkDiff(oldValue, newValue interface{}, keys []string, display []string, out *[]change) {
	oldBranch, oldIsBranch := asBranch(oldValue)
	newBranch, newIsBranch := asBranch(newValue)

	switch {
	case oldIsBranch && newIsBranch:
		diffBranchKeys(oldBranch, newBranch, keys, display, out)
		return
	case oldIsBranch != newIsBranch:
		// A mapping replaced by a scalar or a sequence, or the reverse.
		record(keys, display, out)
		return
	}

	oldList, oldIsList := oldValue.([]interface{})
	newList, newIsList := newValue.([]interface{})
	switch {
	case oldIsList && newIsList:
		diffLists(oldList, newList, keys, display, out)
		return
	case oldIsList != newIsList:
		record(keys, display, out)
		return
	}

	if !reflect.DeepEqual(oldValue, newValue) {
		record(keys, display, out)
	}
}

// Compares two mappings key by key. SOPS branches are ordered slices,
// but reordering the keys of a Kubernetes object carries no meaning, so
// the comparison is by key rather than by position.
func diffBranchKeys(oldBranch, newBranch sops.TreeBranch, keys, display []string, out *[]change) {
	oldKeys := branchKeys(oldBranch)
	newKeys := branchKeys(newBranch)

	names := make([]string, 0, len(oldKeys))
	for name := range oldKeys {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		newValue, ok := newKeys[name]
		if !ok {
			record(append(keys, name), append(display, name), out)
			continue
		}
		walkDiff(oldKeys[name], newValue, append(keys, name), append(display, name), out)
	}

	added := make([]string, 0)
	for name := range newKeys {
		if _, ok := oldKeys[name]; !ok {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	for _, name := range added {
		record(append(keys, name), append(display, name), out)
	}
}

// Compares two sequences positionally. The index is added to the
// display path only; SOPS leaves the encryption path untouched inside a
// sequence, so keys is passed through unchanged.
func diffLists(oldList, newList []interface{}, keys, display []string, out *[]change) {
	longest := len(oldList)
	if len(newList) > longest {
		longest = len(newList)
	}
	for i := 0; i < longest; i++ {
		indexed := appendIndex(display, i)
		if i >= len(oldList) || i >= len(newList) {
			record(keys, indexed, out)
			continue
		}
		walkDiff(oldList[i], newList[i], keys, indexed, out)
	}
}

// record appends one change, copying the path slices because callers build
// them with append on a shared backing array.
func record(keys, display []string, out *[]change) {
	*out = append(*out, change{
		keys:    append([]string(nil), keys...),
		display: strings.Join(display, "."),
	})
}

// Attaches a sequence index to the last segment of a display path,
// yielding "spec.containers[0]" rather than "spec.containers.0".
func appendIndex(display []string, i int) []string {
	out := append([]string(nil), display...)
	if len(out) == 0 {
		return []string{fmt.Sprintf("[%d]", i)}
	}
	out[len(out)-1] = fmt.Sprintf("%s[%d]", out[len(out)-1], i)
	return out
}

// Indexes a branch by its string keys, skipping comments, which
// carry no key of their own.
func branchKeys(branch sops.TreeBranch) map[string]interface{} {
	out := make(map[string]interface{}, len(branch))
	for _, item := range branch {
		if _, isComment := item.Key.(sops.Comment); isComment {
			continue
		}
		key, ok := item.Key.(string)
		if !ok {
			key = fmt.Sprintf("%v", item.Key)
		}
		out[key] = item.Value
	}
	return out
}

// Normalises the shapes SOPS uses for a nested mapping.
func asBranch(v interface{}) (sops.TreeBranch, bool) {
	switch b := v.(type) {
	case sops.TreeBranch:
		return b, true
	case *sops.TreeBranch:
		if b == nil {
			return nil, false
		}
		return *b, true
	default:
		return nil, false
	}
}
