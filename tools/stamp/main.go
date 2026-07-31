// Command stamp records a fingerprint of the Rust sources in a Go constant.
//
// # WHY THIS EXISTS
//
// Go's build cache does not track the static library named in #cgo LDFLAGS.
// Neither form helps: `-L<dir> -l<name>` and a direct path to the .a were both
// measured to leave a stale binary in place after the archive changed. Worse,
// the staleness survives `go clean -cache`, because `go build -o` compares the
// existing output file's embedded build ID - which does not incorporate the
// archive - and concludes it is up to date. The only reliable remedies are to
// delete the output binary, to pass `go build -a`, or to make a Go source file
// change. This program is that source change: rebuilding the Rust rewrites the
// constant, which invalidates the package, which forces the relink.
//
// # WHY IT IS GO AND NOT SHELL
//
// The obvious shell version, `... | sha256sum`, is not portable: OpenBSD and
// FreeBSD have sha256, macOS has shasum, and none of them have sha256sum. Tool
// detection would fix the hash but leave two subtler hazards, because `find`
// and `sort` also differ - and `sort` is locale-dependent, so the same sources
// can order differently on two machines and produce different fingerprints.
// Doing the walk, the ordering and the hashing here removes all three at once,
// and adds no dependency: the Go toolchain is already required to use this
// library at all.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fingerprintLen is how much of the digest ends up in the constant. This only
// needs to make accidental collisions implausible, not resist an attacker.
const fingerprintLen = 16

// sources are the inputs to the fingerprint, named explicitly.
//
// Naming them beats walking all of rust/ in both directions. Walking is
// fail-open: a sparse checkout, an interrupted `git clean`, or dropping the
// vendored patch once its fix lands upstream would each hash some subset and
// report a plausible, wrong fingerprint. Walking is also churn-prone, because
// any untracked .rs/.toml under rust/ - `rust/.cargo/config.toml` is the
// obvious one - would change the committed constant and fail CI for a file
// that is not in the repository.
var sources = []string{
	"rust/arti-ffi/Cargo.toml",
	"rust/arti-ffi/Cargo.lock",
	"rust/arti-ffi/src",
	"rust/vendor",
}

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", filepath.Join("internal", "arti", "libstamp.go"), "generated file, relative to root")
	pkg := flag.String("package", "arti", "package clause for the generated file")
	flag.Parse()

	if err := run(*root, *out, *pkg); err != nil {
		fmt.Fprintln(os.Stderr, "stamp:", err)
		os.Exit(1)
	}
}

func run(root, out, pkg string) error {
	files, err := collect(root)
	if err != nil {
		return err
	}
	// Fail closed. An empty file list would hash to a constant, which would
	// look like success while silently disabling the whole mechanism - the
	// exact failure mode the shell version had when sha256sum was missing.
	if len(files) == 0 {
		return fmt.Errorf("no source files found under %v; refusing to write an empty fingerprint", sources)
	}

	sum, err := fingerprint(root, files)
	if err != nil {
		return err
	}

	target := filepath.Join(root, out)
	next := render(pkg, sum)
	prev, err := os.ReadFile(target)
	if err == nil && bytes.Equal(prev, next) {
		return nil // unchanged; leave the file (and its mtime) alone
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(target, next, 0o644); err != nil {
		return err
	}
	fmt.Printf(">> rust fingerprint is now %s\n", sum)
	return nil
}

// collect returns the paths to fingerprint, slash-separated, relative to root
// and sorted.
//
// Sorting here rather than relying on directory order is what makes the result
// reproducible: filesystems return entries in arbitrary order, and a shell
// `sort` would additionally depend on the locale.
//
// The paths are slash-normalised BEFORE sorting, which matters more than it
// looks. '/' is 0x2F and '\' is 0x5C, so sorting native paths orders a Windows
// checkout differently from a Unix one wherever a directory competes with a
// sibling file - and a different order means a different fingerprint from
// identical sources, which is precisely the divergence this whole design is
// meant to rule out.
func collect(root string) ([]string, error) {
	var files []string
	for _, src := range sources {
		full := filepath.Join(root, filepath.FromSlash(src))
		// Every input must exist. Hashing whatever happens to be present is
		// how you get a well-formed fingerprint for an incomplete tree.
		if _, err := os.Stat(full); err != nil {
			return nil, fmt.Errorf("required source %s: %w", src, err)
		}
		err := filepath.WalkDir(full, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// Build output is derived and changes on every build; dot
				// directories hold editor and VCS state, not sources.
				if d.Name() == "target" || (path != full && strings.HasPrefix(d.Name(), ".")) {
					return fs.SkipDir
				}
				return nil
			}
			switch filepath.Ext(path) {
			case ".rs", ".toml", ".lock":
			default:
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// fingerprint hashes the named files, path and contents both.
func fingerprint(root string, files []string) (string, error) {
	h := sha256.New()
	for _, rel := range files {
		// rel is slash-separated; convert back to open it.
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		// Normalise line endings. A Windows checkout with core.autocrlf=true
		// stores CRLF on disk, which would otherwise fingerprint differently
		// from the identical sources on Linux and break the CI check that
		// asserts the committed value is current.
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))

		// Length-delimited, so that two different file lists cannot
		// concatenate to the same byte stream.
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(data))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:fingerprintLen], nil
}

func render(pkg, sum string) []byte {
	var b strings.Builder
	b.WriteString("// Code generated by `make stamp`. DO NOT EDIT.\n\n")
	b.WriteString("package " + pkg + "\n\n")
	b.WriteString("// rustFingerprint identifies the Rust sources the linked\n")
	b.WriteString("// libarti_ffi.a was built from.\n")
	b.WriteString("//\n")
	b.WriteString("// It exists only to be part of this package's source. Go does not hash\n")
	b.WriteString("// the static library named in #cgo LDFLAGS, so without a Go-visible\n")
	b.WriteString("// change a rebuilt library is silently ignored in favour of a cached\n")
	b.WriteString("// binary. Keeping this in step with the Rust is what makes\n")
	b.WriteString("// `make lib && go build` produce a binary containing the new library.\n")
	b.WriteString("const rustFingerprint = \"" + sum + "\"\n")
	return []byte(b.String())
}
