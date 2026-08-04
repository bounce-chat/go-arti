// Package buildcheck holds tests about how the module is built, rather than
// about what it does. It carries no non-test code on purpose: it must be
// checkable without cgo and without a platform's static archive present.
package buildcheck

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// cgoFile is the file whose #cgo directives decide, for each platform, which
// archive is linked and which system libraries come with it.
const cgoFile = "../arti/cgo.go"

// platforms is every target the Makefile can build. Keep in step with TARGETS,
// ANDROID_TARGETS, openbsd_amd64, freebsd_amd64 and ios_arm64 there.
var platforms = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
	{"openbsd", "amd64"},
	{"freebsd", "amd64"},
	{"android", "arm64"},
	{"android", "arm"},
	{"android", "amd64"},
	{"android", "386"},
	{"ios", "arm64"},
}

// TestEveryPlatformLinksExactlyOneArchive is what the old "cross-compile check"
// CI step was trying to be.
//
// That step ran `GOOS=windows go vet ./...`, which cannot work: cross-compiling
// defaults CGO_ENABLED=0, a file importing "C" is then excluded from the
// package, and every symbol cgo.go defines becomes undefined. It reported a
// wall of errors, was wrapped in `|| true`, and never parsed a single #cgo
// line.
//
// The real risk is this table drifting: a platform with no -L line links
// against whatever the linker finds, a platform matching two lines gets an
// ambiguous search path, and a mistyped tag silently disables a target. All
// three are checkable here, natively, with no cross toolchain and no archive.
func TestEveryPlatformLinksExactlyOneArchive(t *testing.T) {
	directives := parseCgoDirectives(t)

	for _, p := range platforms {
		name := p.goos + "_" + p.goarch
		t.Run(name, func(t *testing.T) {
			tags := tagsFor(p.goos, p.goarch)

			var paths, libs []string
			for _, d := range directives {
				if !d.matches(tags) {
					continue
				}
				if strings.Contains(d.flags, "-L") {
					paths = append(paths, d.flags)
				}
				if strings.Contains(d.flags, "-larti_ffi") {
					libs = append(libs, d.flags)
				}
			}

			if len(paths) != 1 {
				t.Errorf("expected exactly 1 archive search path, got %d: %v", len(paths), paths)
			} else if want := "lib/" + name; !strings.Contains(paths[0], want) {
				// A copy-paste slip here points a platform at another
				// platform's archive, which fails at link time with an error
				// that names neither platform.
				t.Errorf("search path does not point at %s: %s", want, paths[0])
			}

			if len(libs) != 1 {
				t.Errorf("expected exactly 1 line linking -larti_ffi, got %d: %v", len(libs), libs)
			}
		})
	}
}

// TestOpenBSDDoesNotLinkLibdl guards a mistake that is easy to make by copying
// the Linux line: OpenBSD has no libdl, because dlopen lives in libc, and
// asking for it fails the link outright rather than being ignored.
func TestOpenBSDDoesNotLinkLibdl(t *testing.T) {
	for _, d := range parseCgoDirectives(t) {
		if !d.matches(tagsFor("openbsd", "amd64")) {
			continue
		}
		if strings.Contains(d.flags, "-ldl") {
			t.Errorf("openbsd must not link libdl: %s", d.flags)
		}
	}
}

// directive is one `#cgo <constraint> LDFLAGS: <flags>` line.
type directive struct {
	// constraint is the raw tag expression: space separates alternatives,
	// comma separates requirements, and ! negates. An empty constraint
	// applies everywhere.
	constraint string
	flags      string
	line       int
}

func (d directive) String() string { return fmt.Sprintf("cgo.go:%d %s", d.line, d.flags) }

// matches reports whether this directive applies to a build with these tags,
// using cgo's own rule: alternatives are OR'd, requirements within an
// alternative are AND'd.
func (d directive) matches(tags map[string]bool) bool {
	if d.constraint == "" {
		return true
	}
	for _, alt := range strings.Fields(d.constraint) {
		ok := true
		for _, term := range strings.Split(alt, ",") {
			negated := strings.HasPrefix(term, "!")
			term = strings.TrimPrefix(term, "!")
			if tags[term] == negated {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// tagsFor returns the build tags in effect for a platform.
//
// The two aliases are the whole reason the !android and !ios exclusions exist
// in cgo.go: Go sets the linux tag for GOOS=android and the darwin tag for
// GOOS=ios, so without them an Android build would match the glibc line and an
// iOS build the macOS one.
func tagsFor(goos, goarch string) map[string]bool {
	tags := map[string]bool{goos: true, goarch: true, "cgo": true}
	switch goos {
	case "android":
		tags["linux"] = true
	case "ios":
		tags["darwin"] = true
	}
	return tags
}

var cgoLine = regexp.MustCompile(`^#cgo\s+(.*?)LDFLAGS:\s*(.*)$`)

func parseCgoDirectives(t *testing.T) []directive {
	t.Helper()
	data, err := os.ReadFile(cgoFile)
	if err != nil {
		t.Fatalf("reading %s: %v", cgoFile, err)
	}

	var out []directive
	for i, raw := range strings.Split(string(data), "\n") {
		m := cgoLine.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			continue
		}
		out = append(out, directive{
			constraint: strings.TrimSpace(m[1]),
			flags:      strings.TrimSpace(m[2]),
			line:       i + 1,
		})
	}
	// Fail closed: a parser that silently matches nothing would make every
	// assertion below vacuous.
	if len(out) == 0 {
		t.Fatalf("no #cgo LDFLAGS directives found in %s", cgoFile)
	}
	return out
}
