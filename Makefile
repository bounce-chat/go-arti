# Builds the static Arti library that the cgo bindings link against.
#
#   make lib          # build for the host
#   make all          # build every supported target
#   make android      # build every Android ABI
#   make doctor       # report what the toolchain looks like
#   make test         # Rust + Go tests
#
# The result lands in lib/<goos>_<goarch>/libarti_ffi.a, which is where the
# #cgo LDFLAGS in internal/arti/cgo.go look for it. lib/ is not tracked in git: the
# archives are ~150 MB each, far too much to carry in a Go module.
#
# Building from source is the only path. Consuming applications ship their own
# binaries, so there is nothing to gain from distributing prebuilt archives and
# a good deal of release machinery to avoid.

CRATE_DIR := rust/arti-ffi
LIB_NAME  := libarti_ffi.a

# Keep the builder's filesystem layout out of the archive.
#
# Rust embeds absolute source paths for panic locations and diagnostics, which
# means $HOME - and so the builder's username - ends up in anything that links
# this. Remapping replaces them with stable placeholders. The `trim-paths`
# profile option does the same thing but still requires nightly.
#
# Appended to any RUSTFLAGS the caller already set.
REMAP_PATHS := --remap-path-prefix=$(HOME)=/builder --remap-path-prefix=$(CURDIR)=/src
CARGO_FLAGS := RUSTFLAGS="$(RUSTFLAGS) $(REMAP_PATHS)"

GOOS   ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# GOOS/GOARCH -> Rust target triple.
#
# Windows uses the *-gnu triple deliberately: cgo links with MinGW, so an
# MSVC-target .lib would not resolve against the Go toolchain's linker.
TRIPLE_linux_amd64   := x86_64-unknown-linux-gnu
TRIPLE_linux_arm64   := aarch64-unknown-linux-gnu
TRIPLE_darwin_amd64  := x86_64-apple-darwin
TRIPLE_darwin_arm64  := aarch64-apple-darwin
TRIPLE_windows_amd64 := x86_64-pc-windows-gnu

# OpenBSD builds natively only, so it is not in TARGETS. Cross-compiling to it
# would need an OpenBSD sysroot to link SQLite and liblzma against, and OpenBSD
# does not ship one for other hosts to consume. Build it on an OpenBSD machine
# with `gmake lib` - note gmake, since this Makefile uses GNU syntax and
# OpenBSD's make is BSD make.
TRIPLE_openbsd_amd64 := x86_64-unknown-openbsd

# Mobile targets are buildable but not prebuilt, because they need an Android
# NDK or an iOS SDK that CI does not carry.
TRIPLE_android_arm64 := aarch64-linux-android
TRIPLE_android_arm   := armv7-linux-androideabi
TRIPLE_android_amd64 := x86_64-linux-android
TRIPLE_android_386   := i686-linux-android
TRIPLE_ios_arm64     := aarch64-apple-ios

# Built by `make all`.
TARGETS := linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64
# Built by `make android`; each needs the NDK.
ANDROID_TARGETS := android_arm64 android_arm android_amd64 android_386

PLATFORM := $(GOOS)_$(GOARCH)
TRIPLE   := $(TRIPLE_$(PLATFORM))
OUT_DIR  := lib/$(PLATFORM)

#
# Android toolchain.
#
# The crate compiles SQLite and liblzma from C source, so a working cross C
# compiler matters as much as the Rust target. The NDK ships API-versioned
# wrappers (aarch64-linux-android21-clang) and no unversioned
# `aarch64-linux-android-clang`, which is the name the `cc` crate looks for by
# default - hence the explicit CC/AR/linker wiring below. This is all cargo-ndk
# would have done for us, so it is not a dependency.
#
# Override ANDROID_API to raise the minimum supported Android version.
ANDROID_API ?= 21
ANDROID_NDK_DIR ?= $(firstword $(wildcard \
    $(ANDROID_NDK_HOME) $(ANDROID_NDK_ROOT) $(ANDROID_NDK) \
    $(ANDROID_HOME)/ndk/* $(ANDROID_SDK_ROOT)/ndk/* \
    /opt/android-ndk $(HOME)/Android/Sdk/ndk/* $(HOME)/Android/sdk/ndk/*))

ifeq ($(shell uname -s),Darwin)
NDK_HOST_TAG := darwin-x86_64
else
NDK_HOST_TAG := linux-x86_64
endif
NDK_BIN := $(ANDROID_NDK_DIR)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin

# The clang wrapper prefix is not always the Rust triple: 32-bit ARM is
# `armv7a-linux-androideabi` for clang but `armv7-linux-androideabi` for Rust.
NDK_PREFIX_arm64 := aarch64-linux-android
NDK_PREFIX_arm   := armv7a-linux-androideabi
NDK_PREFIX_amd64 := x86_64-linux-android
NDK_PREFIX_386   := i686-linux-android

#
# Cross-compiling Linux targets.
#
# Same reason as Android: SQLite and liblzma are built from C source, so a
# cross C compiler is needed and cargo has to be pointed at it. Building for
# the host architecture needs none of this.
ifeq ($(PLATFORM),linux_arm64)
ifneq ($(shell uname -m),aarch64)
LINUX_CROSS_CC ?= aarch64-linux-gnu-gcc
CARGO_ENV := CC_aarch64_unknown_linux_gnu="$(LINUX_CROSS_CC)" \
             AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
             CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$(LINUX_CROSS_CC)"
endif
endif

# Env var names cargo and the cc crate derive from the target triple.
TRIPLE_UNDER := $(subst -,_,$(TRIPLE))
TRIPLE_UPPER := $(shell echo '$(TRIPLE_UNDER)' | tr 'a-z' 'A-Z')

ifeq ($(GOOS),android)
NDK_CLANG := $(NDK_BIN)/$(NDK_PREFIX_$(GOARCH))$(ANDROID_API)-clang
CARGO_ENV := CC_$(TRIPLE_UNDER)="$(NDK_CLANG)" \
             AR_$(TRIPLE_UNDER)="$(NDK_BIN)/llvm-ar" \
             CARGO_TARGET_$(TRIPLE_UPPER)_LINKER="$(NDK_CLANG)"
endif

# Cross-compiling the Windows target.
#
# Same reason again: the *-pc-windows-gnu triple links with MinGW, and SQLite
# and liblzma are compiled from C source, so the `cc` crate needs the MinGW
# driver it derives from the triple. Nothing has to be wired into CARGO_ENV -
# cc finds x86_64-w64-mingw32-gcc by name - but check-cross tests for it,
# because without it the build spends about two minutes compiling before dying
# deep inside a build script with "error calling dlltool", which names neither
# the missing package nor the target.
ifeq ($(PLATFORM),windows_amd64)
ifneq ($(OS),Windows_NT)
WINDOWS_CROSS_CC ?= x86_64-w64-mingw32-gcc
endif
endif

# Building a macOS target anywhere but macOS needs an Apple SDK, which Apple
# does not license for redistribution. osxcross is the usual way to arrange
# one; CI builds these on macOS runners instead.
ifeq ($(GOOS),darwin)
ifneq ($(shell uname -s),Darwin)
DARWIN_CROSS_CC ?= $(if $(filter arm64,$(GOARCH)),oa64-clang,o64-clang)
CARGO_ENV := CC_$(TRIPLE_UNDER)="$(DARWIN_CROSS_CC)" \
             CARGO_TARGET_$(TRIPLE_UPPER)_LINKER="$(DARWIN_CROSS_CC)"
endif
endif

# Whichever cross compiler this target needs, if any. At most one of the three
# is ever set, so concatenating them names it. Defined after all three blocks
# because := evaluates immediately; `doctor` reports on it.
CROSS_CC := $(LINUX_CROSS_CC)$(DARWIN_CROSS_CC)$(WINDOWS_CROSS_CC)

.PHONY: lib all android test test-rust test-go check-features arti-check \
        arti-update clean check-target check-android check-cross doctor

check-target:
ifeq ($(TRIPLE),)
	$(error unsupported target $(GOOS)/$(GOARCH); supported: $(TARGETS) $(ANDROID_TARGETS) openbsd_amd64 ios_arm64)
endif
	@# Only rustup can add standard libraries, so only ask it when it is what
	@# manages this toolchain. A distribution-packaged rustc (OpenBSD ports,
	@# Debian, Fedora) has no rustup and ships only the host's standard
	@# library - which is exactly what a native build needs, so an absent
	@# rustup means "nothing to check", not "not installed".
	@#
	@# The toolchain check comes first because rustup installed with no default
	@# toolchain fails the target check too, and the advice it gives - `rustup
	@# target add` - fails as well, with "no installed toolchains". Telling
	@# someone to run a command that cannot work is worse than saying nothing.
	@command -v rustup >/dev/null 2>&1 || exit 0; \
	rustup show active-toolchain >/dev/null 2>&1 || { \
	    echo "make: rustup is installed but has no default toolchain, so there"; \
	    echo "      is no rustc to build with."; \
	    echo "      fix it with: rustup default stable"; \
	    exit 1; \
	}; \
	rustup target list --installed 2>/dev/null | grep -qx '$(TRIPLE)' || { \
	    echo "make: the Rust standard library for $(TRIPLE) is not installed."; \
	    echo "      install it with: rustup target add $(TRIPLE)"; \
	    exit 1; \
	}

## Fail early and legibly when the NDK is missing or incomplete.
check-android:
ifeq ($(GOOS),android)
ifeq ($(ANDROID_NDK_DIR),)
	$(error no Android NDK found; set ANDROID_NDK_HOME to your NDK directory)
endif
	@test -x "$(NDK_CLANG)" || { \
	    echo "make: no such compiler: $(NDK_CLANG)"; \
	    echo "      the NDK at $(ANDROID_NDK_DIR) does not provide API level $(ANDROID_API) for $(GOARCH)."; \
	    echo "      available levels:"; \
	    ls "$(NDK_BIN)" 2>/dev/null | sed -n 's/^$(NDK_PREFIX_$(GOARCH))\([0-9]*\)-clang$$/        \1/p' | tr '\n' ' '; \
	    echo; \
	    echo "      pass a supported one with: make lib GOOS=android GOARCH=$(GOARCH) ANDROID_API=<level>"; \
	    exit 1; \
	}
endif

## Fail early when a cross C compiler is needed but absent.
check-cross:
ifdef DARWIN_CROSS_CC
	@command -v $(DARWIN_CROSS_CC) >/dev/null || { \
	    echo "make: $(DARWIN_CROSS_CC) not found."; \
	    echo "      Building $(PLATFORM) from $$(uname -s) needs an Apple SDK, which"; \
	    echo "      Apple does not license for redistribution, so there is no package"; \
	    echo "      to install. Either build on a Mac, let CI do it (the release"; \
	    echo "      workflow uses macOS runners), or set up osxcross and put"; \
	    echo "      $(DARWIN_CROSS_CC) on PATH."; \
	    exit 1; \
	}
endif
ifdef WINDOWS_CROSS_CC
	@command -v $(WINDOWS_CROSS_CC) >/dev/null || { \
	    echo "make: $(WINDOWS_CROSS_CC) not found."; \
	    echo "      cross-compiling $(PLATFORM) needs MinGW: the *-pc-windows-gnu"; \
	    echo "      triple links with it rather than MSVC, and SQLite and liblzma"; \
	    echo "      are compiled from C source."; \
	    echo "      Arch:   sudo pacman -S mingw-w64-gcc"; \
	    echo "      Debian: sudo apt install gcc-mingw-w64-x86-64"; \
	    exit 1; \
	}
endif
ifdef LINUX_CROSS_CC
	@command -v $(LINUX_CROSS_CC) >/dev/null || { \
	    echo "make: $(LINUX_CROSS_CC) not found."; \
	    echo "      cross-compiling $(PLATFORM) needs it, because SQLite and liblzma"; \
	    echo "      are compiled from C source."; \
	    echo "      Arch:   sudo pacman -S aarch64-linux-gnu-gcc"; \
	    echo "      Debian: sudo apt install gcc-aarch64-linux-gnu"; \
	    exit 1; \
	}
endif

## Build the library from source for GOOS/GOARCH.
lib: check-target check-android check-cross
	@echo ">> building $(LIB_NAME) for $(PLATFORM) ($(TRIPLE))"
	cd $(CRATE_DIR) && $(CARGO_FLAGS) $(CARGO_ENV) cargo build --release --target $(TRIPLE)
	@mkdir -p $(OUT_DIR)
	cp $(CRATE_DIR)/target/$(TRIPLE)/release/$(LIB_NAME) $(OUT_DIR)/$(LIB_NAME)
	@echo ">> wrote $(OUT_DIR)/$(LIB_NAME)"
	@$(MAKE) --no-print-directory stamp

# Record a fingerprint of the Rust sources in a Go constant.
#
# Go's build cache does not treat the static library as an input: it reaches the
# toolchain through `#cgo LDFLAGS`, which is not hashed. Without this, changing
# the Rust and running `go build` silently reuses a cached executable linked
# against the previous archive - the binary and the library disagree, and
# nothing says so. Writing the fingerprint into a Go source file makes a Rust
# change a Go change, which forces the relink.
#
# That only works because internal/arti/arti.go refers to the constant from
# RustFingerprint(). An unreferenced constant is not emitted into the package
# object at all, so the object stays byte-identical whatever the fingerprint
# says, the link action ID does not move, and the stale binary is reused
# anyway. Measured with `go tool buildid`, not assumed: three different
# fingerprint values all produced content ID GoYe7_KiWL6DBHbInvTP until the
# accessor existed. TestRustFingerprintIsUsed fails if it is ever tidied away.
#
# The hash covers the sources rather than the archive so that rebuilding
# unchanged code does not churn the file.
#
# The work is done by a Go program rather than inline shell on purpose. The
# obvious `| sha256sum` is GNU-only: OpenBSD and FreeBSD ship sha256, macOS
# ships shasum, and none of them ship sha256sum. Detecting the tool would fix
# the hash but not `find` and `sort`, which also differ - and `sort` is
# locale-dependent, so identical sources can order differently on two machines
# and produce different fingerprints. tools/stamp does the walk, the ordering
# and the hashing itself, which removes all three, and costs nothing because
# the Go toolchain is already required. Please do not "simplify" it back.
#
# The empty GOOS/GOARCH/CGO_ENABLED/GOFLAGS are load-bearing. GNU make exports
# variables set on the command line into every recipe and every sub-make, so
# `make lib GOOS=windows GOARCH=amd64` puts GOOS=windows into this recipe's
# environment by way of the $(MAKE) stamp above. A bare `go run` would then
# cross-compile the generator and fail to execute it ("exec format error"),
# breaking `make all`, `make android` and every cross build - after the cargo
# build had already run. An empty assignment reads as "unset" to cmd/go and is
# a POSIX assignment prefix, so it is safe in ksh, dash and bash alike.
.PHONY: stamp
stamp:
	@GOOS= GOARCH= CGO_ENABLED= GOFLAGS= go run ./tools/stamp

## Build every supported target.
all:
	@for target in $(TARGETS); do \
	    goos=$${target%_*}; goarch=$${target#*_}; \
	    $(MAKE) lib GOOS=$$goos GOARCH=$$goarch || exit 1; \
	done

## Build every Android ABI. Needs the NDK; see `make doctor`.
android:
	@for target in $(ANDROID_TARGETS); do \
	    goos=$${target%_*}; goarch=$${target#*_}; \
	    $(MAKE) lib GOOS=$$goos GOARCH=$$goarch || exit 1; \
	done

## Report what the toolchain looks like for the current target.
doctor:
	@echo "target:      $(GOOS)/$(GOARCH) -> $(if $(TRIPLE),$(TRIPLE),UNSUPPORTED)"
	@# Same reasoning as check-target: no rustup means there is nothing for
	@# rustup to check, not a broken toolchain. Telling someone on an OpenBSD
	@# ports rustc to run `rustup target add` is advice they cannot follow.
	@echo "rust target: $$(command -v rustup >/dev/null 2>&1 || { echo 'n/a (no rustup; using the system rustc)'; exit 0; }; rustup target list --installed 2>/dev/null | grep -qx '$(TRIPLE)' && echo installed || echo 'MISSING - rustup target add $(TRIPLE)')"
	@echo "android ndk: $(if $(ANDROID_NDK_DIR),$(ANDROID_NDK_DIR),none found)"
	@echo "android cc:  $(if $(filter android,$(GOOS)),$(NDK_CLANG) $(if $(wildcard $(NDK_CLANG)),(ok),(MISSING)),n/a)"
	@echo "cross cc:    $(if $(CROSS_CC),$(CROSS_CC) $$(command -v $(CROSS_CC) >/dev/null && echo '(ok)' || echo '(MISSING)'),n/a)"

# The feature set arti-client is expected to resolve to.
#
# Arti warns that cargo feature unification can quietly enable features you did
# not ask for, including experimental ones. Two of these are deliberate and
# load-bearing, so the answer is not "use none" but "notice when it changes":
#
#   experimental-api    launch_onion_service_with_hsid, which is how a
#                       caller-supplied identity key is used at all. Without it
#                       Arti generates and persists its own key and a saved
#                       .onion address cannot be carried across a restart.
#   ephemeral-keystore  keeps those identity keys in memory, matching the
#                       lifetime an embedding application expects and keeping
#                       them off disk.
#
# Anything appearing here that is not in this list arrived by unification and
# should be understood before it ships.
ARTI_FEATURES := __is_experimental __is_nonadditive bridge-client compression \
                 ephemeral-keystore experimental-api keymgr onion-service-client \
                 onion-service-service pt-client rustls static-sqlite tokio \
                 tor-hsclient tor-hscrypto tor-hsservice tor-ptmgr

## Fail if arti-client resolves to a different feature set than expected.
check-features:
	@actual=$$(cd $(CRATE_DIR) && cargo tree -f '{p} {f}' --depth 1 2>/dev/null \
	    | grep 'arti-client v' \
	    | sed 's/.*arti-client v[0-9.]* //' \
	    | tr ',' '\n' | sed 's/^ *//;s/ *$$//' | grep -v '^$$' | LC_ALL=C sort | tr '\n' ' '); \
	expected=$$(printf '%s\n' $(ARTI_FEATURES) | LC_ALL=C sort | tr '\n' ' '); \
	if [ -z "$$actual" ]; then \
	    echo "make: could not read arti-client's feature set. cargo says:"; \
	    cd $(CRATE_DIR) && cargo tree -f '{p} {f}' --depth 1 >/dev/null; \
	    exit 1; \
	fi; \
	if [ "$$actual" != "$$expected" ]; then \
	    echo "make: arti-client's feature set has changed."; \
	    echo "      expected: $$expected"; \
	    echo "      actual:   $$actual"; \
	    echo "      Reconcile ARTI_FEATURES in the Makefile once you understand why."; \
	    exit 1; \
	fi; \
	echo ">> arti-client features unchanged"

#
# Keeping up with Arti.
#
# The Arti release version appears in five places: the tor-*/arti-* pins in
# rust/arti-ffi/Cargo.toml, Cargo.lock, ARTI_VERSION and ARTI_VERSION_C in
# src/lib.rs, and the table in README.md. `arti-update` moves the first four
# together; the README and the live tests are on you.
ARTI_PINNED := $(shell sed -n 's/^pub const ARTI_VERSION: &str = "\(.*\)";/\1/p' \
                   $(CRATE_DIR)/src/lib.rs)

## Report the pinned Arti version against what is published.
arti-check:
	@echo "arti pinned:    $(ARTI_PINNED)"
	@latest=$$(cargo search arti-client --limit 1 2>/dev/null \
	    | sed -n 's/^arti-client = "\([^"]*\)".*/\1/p'); \
	echo "arti published: $${latest:-unknown}"; \
	series=$$(echo "$$latest" | cut -d. -f1,2); \
	if [ -z "$$latest" ]; then echo ">> could not reach crates.io"; \
	elif [ "$$series" = "$(ARTI_PINNED)" ]; then echo ">> up to date"; \
	else echo ">> newer release available; run 'make arti-update'"; fi
	@echo
	@echo "vendored patches:"
	@latest=$$(cargo search saturating-time --limit 1 2>/dev/null \
	    | sed -n 's/^saturating-time = "\([^"]*\)".*/\1/p'); \
	echo "  saturating-time published: $${latest:-unknown} (vendored: 0.4.0)"; \
	if [ -n "$$latest" ] && [ "$$latest" != "0.4.0" ]; then \
	    echo "  >> a new release exists; check whether the Windows hang is fixed"; \
	    echo "     upstream and drop rust/vendor/saturating-time if so."; \
	else \
	    echo "  >> still the version the patch was written against"; \
	fi

## Bump the Arti dependencies and run everything that does not need a network.
arti-update:
	@latest=$$(cargo search arti-client --limit 1 2>/dev/null \
	    | sed -n 's/^arti-client = "\([^"]*\)".*/\1/p'); \
	if [ -z "$$latest" ]; then echo "make: could not reach crates.io"; exit 1; fi; \
	series=$$(echo "$$latest" | cut -d. -f1,2); \
	if [ "$$series" = "$(ARTI_PINNED)" ]; then \
	    echo ">> already on $(ARTI_PINNED); nothing to bump"; \
	else \
	    echo ">> $(ARTI_PINNED) -> $$series"; \
	    for f in $(CRATE_DIR)/Cargo.toml $(CRATE_DIR)/src/lib.rs; do \
	        sed 's/version = "$(ARTI_PINNED)"/version = "'$$series'"/g; \
	             s/= "$(ARTI_PINNED)"$$/= "'$$series'"/g; \
	             s/"Arti $(ARTI_PINNED)\\0"/"Arti '$$series'\\0"/; \
	             s/ARTI_VERSION: &str = "$(ARTI_PINNED)"/ARTI_VERSION: \&str = "'$$series'"/' \
	            "$$f" > "$$f.new" && mv "$$f.new" "$$f" || exit 1; \
	    done; \
	fi
	@echo ">> resolving"
	@# The pipeline's status would be tail's, so a failed resolution would fall
	@# through into check-features, test-rust, lib and test-go against an
	@# inconsistent lockfile.
	@out=$$(cd $(CRATE_DIR) && cargo update 2>&1) || { \
	    printf '%s\n' "$$out" | tail -n 20; \
	    echo "make: cargo update failed; not continuing into the build"; \
	    exit 1; \
	}; \
	printf '%s\n' "$$out" | tail -n 20
	@echo ">> the auxiliary crates (safelog, fs-mistrust) version separately;"
	@echo "   if resolution failed above, they are the usual reason."
	@$(MAKE) --no-print-directory check-features
	@$(MAKE) --no-print-directory test-rust
	@$(MAKE) --no-print-directory lib
	@$(MAKE) --no-print-directory test-go
	@echo
	@echo ">> offline checks passed. Still to do by hand:"
	@echo "     - go test -tags integration -timeout 40m ./...   (the real check)"
	@echo "     - update the arti version in README.md"
	@echo "     - re-read the Arti changelog for behaviour changes; the status"
	@echo "       enums and the experimental APIs we use are not stable"

test: check-features test-rust test-go

test-rust:
	cd $(CRATE_DIR) && $(CARGO_FLAGS) cargo test

## Requires lib/$(PLATFORM)/$(LIB_NAME); run `make lib` first.
test-go:
	go test ./...

clean:
	cd $(CRATE_DIR) && cargo clean
	rm -rf lib
