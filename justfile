# The gates from .github/workflows/build.yml, runnable before a push.
#
# CI fans these out over macOS, Ubuntu and Windows on stable and nightly.
# Locally this runs one OS and the stable toolchain only; the nightly cells are
# allowed to fail in CI and are not repeated here.

[doc("Run the same gates as CI before pushing; one OS, stable only")]
ci-check:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "==> fmt"
    cargo fmt --all -- --check

    echo "==> clippy"
    cargo clippy --all-targets -- -D warnings

    echo "==> check"
    cargo check

    # The hash is a type parameter, not a feature, so SHA-512 (the default) and
    # SHA-1 are both exercised by the default run; the extra runs cover the
    # feature-gated SHA-1 groups.
    echo "==> test (default)"
    cargo test

    echo "==> test (appendix B)"
    cargo test --features test-rfc-5054-appendix-b --no-default-features --lib

    echo "==> test (sha1 groups)"
    cargo test --features hash-sha1 --no-default-features --lib

    echo "==> test (wow)"
    cargo test --features wow-1-12-1 --no-default-features --lib

    # Features only add, so everything on at once must hold too.
    echo "==> test (all features)"
    cargo test --all-features

    echo "==> docs"
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

    echo "==> audit (advisory; CI allows this job to fail)"
    if command -v cargo-deny >/dev/null 2>&1; then
        cargo deny check advisories bans sources || true
    else
        echo "cargo-deny not installed, skipping"
    fi

[doc("Point git at the checked-in hooks; run once per clone")]
install-hooks:
    git config core.hooksPath .githooks
    echo "pre-push hook installed"
