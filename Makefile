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
# means $HOME — and so the builder's username — ends up in anything that links
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
# default — hence the explicit CC/AR/linker wiring below. This is all cargo-ndk
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

.PHONY: lib all android test test-rust test-go check-features arti-check \
        arti-update clean check-target check-android check-cross doctor

check-target:
ifeq ($(TRIPLE),)
	$(error unsupported target $(GOOS)/$(GOARCH); supported: $(TARGETS) $(ANDROID_TARGETS) ios_arm64)
endif
	@rustup target list --installed 2>/dev/null | grep -qx '$(TRIPLE)' || { \
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
# against the previous archive — the binary and the library disagree, and
# nothing says so. Writing the fingerprint into a Go source file makes a Rust
# change a Go change, which forces the relink.
#
# The hash covers the sources rather than the archive so that rebuilding
# unchanged code does not churn the file.
.PHONY: stamp
stamp:
	@hash=$$(cat $(CRATE_DIR)/Cargo.toml $(CRATE_DIR)/Cargo.lock \
	    $$(find $(CRATE_DIR)/src rust/vendor -type f \( -name '*.rs' -o -name '*.toml' \) | sort) \
	    | sha256sum | cut -c1-16); \
	tmp=$$(mktemp); \
	{ \
	  echo "// Code generated by \`make stamp\`. DO NOT EDIT."; \
	  echo; \
	  echo "package arti"; \
	  echo; \
	  echo "// rustFingerprint identifies the Rust sources the linked"; \
	  echo "// libarti_ffi.a was built from."; \
	  echo "//"; \
	  echo "// It exists only to be part of this package's source. Go does not hash"; \
	  echo "// the static library named in #cgo LDFLAGS, so without a Go-visible"; \
	  echo "// change a rebuilt library is silently ignored in favour of a cached"; \
	  echo "// binary. Keeping this in step with the Rust is what makes"; \
	  echo "// \`make lib && go build\` produce a binary containing the new library."; \
	  echo "const rustFingerprint = \"$$hash\""; \
	} > $$tmp; \
	if cmp -s $$tmp internal/arti/libstamp.go; then \
	  rm -f $$tmp; \
	else \
	  mv $$tmp internal/arti/libstamp.go; \
	  echo ">> rust fingerprint is now $$hash"; \
	fi

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
	@echo "rust target: $$(rustup target list --installed 2>/dev/null | grep -qx '$(TRIPLE)' && echo installed || echo 'MISSING - rustup target add $(TRIPLE)')"
	@echo "android ndk: $(if $(ANDROID_NDK_DIR),$(ANDROID_NDK_DIR),none found)"
	@echo "android cc:  $(if $(filter android,$(GOOS)),$(NDK_CLANG) $(if $(wildcard $(NDK_CLANG)),(ok),(MISSING)),n/a)"
	@echo "cross cc:    $(if $(LINUX_CROSS_CC)$(DARWIN_CROSS_CC),$(LINUX_CROSS_CC)$(DARWIN_CROSS_CC) $$(command -v $(LINUX_CROSS_CC)$(DARWIN_CROSS_CC) >/dev/null && echo '(ok)' || echo '(MISSING)'),n/a)"

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
	    | tr ',' '\n' | sed 's/^ *//;s/ *$$//' | grep -v '^$$' | sort | tr '\n' ' '); \
	expected=$$(printf '%s\n' $(ARTI_FEATURES) | sort | tr '\n' ' '); \
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
	case "$$latest" in \
	    "$(ARTI_PINNED)"*) echo ">> up to date";; \
	    "") echo ">> could not reach crates.io";; \
	    *) echo ">> newer release available; run 'make arti-update'";; \
	esac
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
	    sed -i 's/version = "$(ARTI_PINNED)"/version = "'$$series'"/g; s/= "$(ARTI_PINNED)"$$/= "'$$series'"/g' \
	        $(CRATE_DIR)/Cargo.toml; \
	    sed -i 's/"Arti $(ARTI_PINNED)\\0"/"Arti '$$series'\\0"/; s/ARTI_VERSION: &str = "$(ARTI_PINNED)"/ARTI_VERSION: \&str = "'$$series'"/' \
	        $(CRATE_DIR)/src/lib.rs; \
	fi
	@echo ">> resolving"
	@cd $(CRATE_DIR) && cargo update 2>&1 | tail -20
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
