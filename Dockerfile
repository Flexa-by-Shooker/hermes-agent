# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG SOURCE_DATE_EPOCH=1783793773
ARG DEBIAN_SNAPSHOT=20260718T000000Z

FROM ghcr.io/astral-sh/uv:0.11.29-python3.13-trixie@sha256:d880a6830733cadff8d92e4f7fda20d9a23985f7c198183ef7e5f86bea170cf8 AS uv_source
# Node 22 LTS source stage. Debian trixie's bundled nodejs is pinned to 20.x
# which reached EOL in April 2026 — we copy node + npm + corepack from the
# upstream node:22 image instead so we can stay on a supported LTS without
# waiting for Debian 14 (forky, ~mid-2027).  Bookworm-based slim image used
# so the produced binary links against glibc 2.36, which runs cleanly on
# our Debian 13 (trixie, glibc 2.41) runtime.  Bumping to a new Node major
# is a one-line ARG change; see #4977.
FROM node:22-bookworm-slim@sha256:7af03b14a13c8cdd38e45058fd957bf00a72bbe17feac43b1c15a689c029c732 AS node_source
# Replace the npm tree bundled in the pinned Node image with an independently
# checksum-locked release. npm 11.18.0 carries sigstore 4.1.1 and picomatch
# 4.0.4, closing the fixable HIGH findings in the copied npm installation.
ADD --checksum=sha256:73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e https://registry.npmjs.org/npm/-/npm-11.18.0.tgz /tmp/npm.tgz
RUN set -eu; \
    printf '%s  %s\n' '73f6155215ebabf4ed96dca1f567c2372cc713c33af2e5b9b62fde4e92373e2e' /tmp/npm.tgz | sha256sum -c -; \
    rm -rf /usr/local/lib/node_modules/npm; \
    mkdir -p /usr/local/lib/node_modules/npm; \
    tar -xzf /tmp/npm.tgz -C /usr/local/lib/node_modules/npm --strip-components=1; \
    test "$(node -p 'require("/usr/local/lib/node_modules/npm/package.json").version')" = '11.18.0'; \
    test "$(node -p 'require("/usr/local/lib/node_modules/npm/node_modules/sigstore/package.json").version')" = '4.1.1'; \
    test "$(node -p 'require("/usr/local/lib/node_modules/npm/node_modules/tinyglobby/node_modules/picomatch/package.json").version')" = '4.0.4'; \
    rm /tmp/npm.tgz

FROM debian:13.4@sha256:e2d08da6f42ef4b09b165d55528a12727aeed8240dc9edf888e3ec07e10ef9da AS build
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT

# Disable Python stdout buffering to ensure logs are printed immediately.
# Do not write .pyc files at runtime: /opt/hermes is immutable in the
# published container and writable state belongs under /var/lib/hermes.
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV TZ=UTC
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Store Playwright browsers outside the volume mount so the build-time
# install stays separate from the governed runtime-state bind mount.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/hermes/.playwright

# Install system dependencies in one layer, clear APT cache.
# tini was previously PID 1 to reap orphaned zombie processes (MCP stdio
# subprocesses, git, bun, etc.) that would otherwise accumulate when hermes
# ran as PID 1. See #15012. Phase 2 of the s6-overlay supervision plan
# replaces tini with s6-overlay's /init (PID 1 = s6-svscan), which reaps
# zombies non-blockingly on SIGCHLD and additionally supervises the main
# hermes process, the dashboard, and per-profile gateways.
RUN set -eu; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf '%s\n' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/" \
        'Suites: trixie trixie-updates' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        'Check-Valid-Until: no' \
        '' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/" \
        'Suites: trixie-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        'Check-Valid-Until: no' \
        > /etc/apt/sources.list.d/debian-snapshot.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl iputils-ping python3 python-is-python3 ripgrep ffmpeg \
        gcc g++ make cmake python3-dev python3-venv libffi-dev libolm-dev procps \
        git openssh-client docker-cli xz-utils unzip; \
    rm -rf /var/lib/apt/lists/* /var/log/apt/*; \
    rm -f /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache

# ---------- s6-overlay install ----------
# s6-overlay provides supervision for the main hermes process, the dashboard,
# and per-profile gateways. /init becomes PID 1 below — see ENTRYPOINT.
#
# Multi-arch: BuildKit auto-populates TARGETARCH (amd64 / arm64). s6-overlay
# uses tarball names keyed on the kernel arch string (x86_64 / aarch64), so
# we map between them inline. The noarch + symlinks tarballs are
# architecture-independent and reused as-is.
#
# We use `curl` instead of `ADD` for the per-arch tarball because `ADD`
# evaluates its URL at parse time, before any ARG / TARGETARCH substitution
# — splitting one URL per arch into two ADDs would download both on every
# build and leave dead bytes in the cache. A single curl + arch-keyed URL
# is simpler and cache-friendlier.
#
# Supply-chain integrity: every tarball is checksum-verified against the
# upstream-published SHA256. To bump S6_OVERLAY_VERSION, fetch the four
# `.sha256` files from the corresponding release and update the ARGs. The
# checksum lookup happens during build, so a compromised release artifact
# fails the build loudly instead of silently producing a tampered image.
ARG S6_OVERLAY_VERSION=3.2.3.0
ARG S6_OVERLAY_NOARCH_SHA256=b720f9d9340efc8bb07528b9743813c836e4b02f8693d90241f047998b4c53cf
ARG S6_OVERLAY_X86_64_SHA256=a93f02882c6ed46b21e7adb5c0add86154f01236c93cd82c7d682722e8840563
ARG S6_OVERLAY_AARCH64_SHA256=0952056ff913482163cc30e35b2e944b507ba1025d78f5becbb89367bf344581
ARG S6_OVERLAY_SYMLINKS_SHA256=a60dc5235de3ecbcf874b9c1f18d73263ab99b289b9329aa950e8729c4789f0e
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp/
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-symlinks-noarch.tar.xz /tmp/
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
        amd64) s6_arch="x86_64"; s6_arch_sha="${S6_OVERLAY_X86_64_SHA256}" ;; \
        arm64) s6_arch="aarch64"; s6_arch_sha="${S6_OVERLAY_AARCH64_SHA256}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH} for s6-overlay" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 -o /tmp/s6-overlay-arch.tar.xz \
        "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${s6_arch}.tar.xz"; \
    { \
        printf '%s  %s\n' "${S6_OVERLAY_NOARCH_SHA256}" /tmp/s6-overlay-noarch.tar.xz; \
        printf '%s  %s\n' "${s6_arch_sha}" /tmp/s6-overlay-arch.tar.xz; \
        printf '%s  %s\n' "${S6_OVERLAY_SYMLINKS_SHA256}" /tmp/s6-overlay-symlinks-noarch.tar.xz; \
    } > /tmp/s6-overlay.sha256; \
    sha256sum -c /tmp/s6-overlay.sha256; \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-arch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-symlinks-noarch.tar.xz; \
    rm /tmp/s6-overlay-*.tar.xz /tmp/s6-overlay.sha256; \
    # #34192: backward-compat shim for orchestration templates that still\
    # reference the legacy /usr/bin/tini entrypoint (e.g. Hostinger's\
    # 'Hermes WebUI' catalog). The image has moved to s6-overlay /init\
    # as PID 1 (see ENTRYPOINT below + the migration comment at the top\
    # of this file), but external wrappers pinned to /usr/bin/tini will\
    # crash with 'tini: No such file or directory' on startup. The shim\
    # symlinks /usr/bin/tini -> /init so legacy wrappers exec the right\
    # PID-1 reaper without behavior change for users on the current\
    # ENTRYPOINT. Safe to drop once the affected catalogs are updated.\
    ln -sf /init /usr/bin/tini

# Non-root user for runtime; UID can be overridden via HERMES_UID at runtime
RUN set -eu; \
    epoch_days=$((SOURCE_DATE_EPOCH / 86400)); \
    printf 'hermes:x:10000:10000::/var/lib/hermes:/bin/sh\n' >> /etc/passwd; \
    printf 'hermes:x:10000:\n' >> /etc/group; \
    printf 'hermes:!:%s:0:99999:7:::\n' "${epoch_days}" >> /etc/shadow; \
    printf 'hermes:!::\n' >> /etc/gshadow; \
    install -d -o 10000 -g 10000 -m 0755 /var/lib/hermes; \
    rm -f /var/log/lastlog /var/log/faillog

COPY --chmod=0755 --from=uv_source /usr/local/bin/uv /usr/local/bin/uvx /usr/local/bin/

# Node 22 LTS: copy the node binary plus the bundled npm + corepack JS
# installs from the upstream image.  npm and npx are recreated as symlinks
# because they're symlinks in the source image (and need to live on PATH).
# See node_source stage at the top of the file for the version-bump
# rationale (#4977).
COPY --chmod=0755 --from=node_source /usr/local/bin/node /usr/local/bin/
COPY --from=node_source /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
COPY --from=node_source /usr/local/lib/node_modules/corepack /usr/local/lib/node_modules/corepack
RUN ln -sf /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && \
    ln -sf /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx && \
    ln -sf /usr/local/lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack

WORKDIR /opt/hermes

# ---------- Layer-cached dependency install ----------
# Copy only package manifests first so npm install + Playwright are cached
# unless the lockfiles themselves change.
#
# ui-tui/packages/hermes-ink/ is copied IN FULL (not just its manifests)
# because it is referenced as a `file:` workspace dependency from
# ui-tui/package.json.  Copying the tree up front lets npm resolve the
# workspace to real content instead of stopping at a bare package.json.
COPY package.json package-lock.json ./
COPY web/package.json web/
COPY ui-tui/package.json ui-tui/
COPY ui-tui/packages/hermes-ink/ ui-tui/packages/hermes-ink/
# apps/shared/ is copied IN FULL because web/package.json references it as a
# `file:` workspace dependency (same pattern as hermes-ink above).
COPY apps/shared/ apps/shared/

# `npm_config_install_links=false` forces npm to install `file:` deps as
# symlinks instead of copies.  This is the default since npm 10+, which is
# what the image ships now (via the node:22 source stage).  We set it
# explicitly anyway as defense-in-depth: the previous Debian-bundled npm
# 9.x defaulted to install-as-copy, which produced a hidden
# node_modules/.package-lock.json that permanently disagreed with the root
# lock on the @hermes/ink entry, tripped the TUI launcher's
# `_tui_need_npm_install()` check on every startup, and triggered a
# runtime `npm install` that then failed with EACCES.  Keeping the env
# guards against a future regression if the source npm version changes.
ENV npm_config_install_links=false

# Playwright's browser payloads are installed from exact, checksum-locked
# archives instead of an npx transaction and a mutable CDN response. The paths
# and completion markers match Playwright 1.61.1's chromium-headless-shell 1228
# and ffmpeg 1011 registry contract.
ADD --checksum=sha256:410c9407d5de3fea80d9398666be06f2aa09154a3fa7b327dc254e336bb4c4b7 https://cdn.playwright.dev/builds/cft/149.0.7827.55/linux64/chrome-headless-shell-linux64.zip /tmp/playwright-chromium.zip
ADD --checksum=sha256:ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc https://cdn.playwright.dev/dbazure/download/playwright/builds/ffmpeg/1011/ffmpeg-linux.zip /tmp/playwright-ffmpeg.zip
RUN set -eu; \
    npm install --prefer-offline --no-audit; \
    printf '%s  %s\n' \
        '410c9407d5de3fea80d9398666be06f2aa09154a3fa7b327dc254e336bb4c4b7' \
        /tmp/playwright-chromium.zip | sha256sum -c -; \
    printf '%s  %s\n' \
        'ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc' \
        /tmp/playwright-ffmpeg.zip | sha256sum -c -; \
    install -d -m 0755 \
        /opt/hermes/.playwright/chromium_headless_shell-1228 \
        /opt/hermes/.playwright/ffmpeg-1011; \
    unzip -q /tmp/playwright-chromium.zip \
        -d /opt/hermes/.playwright/chromium_headless_shell-1228; \
    unzip -q /tmp/playwright-ffmpeg.zip \
        -d /opt/hermes/.playwright/ffmpeg-1011; \
    chmod 0755 \
        /opt/hermes/.playwright/chromium_headless_shell-1228/chrome-headless-shell-linux64/chrome-headless-shell \
        /opt/hermes/.playwright/ffmpeg-1011/ffmpeg-linux; \
    touch \
        /opt/hermes/.playwright/chromium_headless_shell-1228/INSTALLATION_COMPLETE \
        /opt/hermes/.playwright/chromium_headless_shell-1228/DEPENDENCIES_VALIDATED \
        /opt/hermes/.playwright/ffmpeg-1011/INSTALLATION_COMPLETE \
        /opt/hermes/.playwright/ffmpeg-1011/DEPENDENCIES_VALIDATED; \
    rm -f /tmp/playwright-chromium.zip /tmp/playwright-ffmpeg.zip; \
    npm cache clean --force

# Debian Snapshot hotfix applied after Playwright's own APT transaction so the
# final filesystem is provably the fixed amd64 libcap2 package. The governed
# runtime-image source lock supports linux/amd64 only; a future multi-arch
# build must add a separately hashed package for each architecture.
ADD --checksum=sha256:f8db64b636eb3e4f805b3f5f62cc32b99beec92df49920a9c24d34902bba0ce9 https://snapshot.debian.org/file/9d57cee3a8050e82ebd1ba078b5767a321bbf5ad /tmp/libcap2.deb
RUN set -eu; \
    test "${TARGETARCH:-amd64}" = 'amd64'; \
    printf '%s  %s\n' 'f8db64b636eb3e4f805b3f5f62cc32b99beec92df49920a9c24d34902bba0ce9' /tmp/libcap2.deb | sha256sum -c -; \
    test "$(dpkg-deb -f /tmp/libcap2.deb Package)" = 'libcap2'; \
    test "$(dpkg-deb -f /tmp/libcap2.deb Architecture)" = 'amd64'; \
    test "$(dpkg-deb -f /tmp/libcap2.deb Version)" = '1:2.75-10+deb13u1'; \
    dpkg -i /tmp/libcap2.deb; \
    test "$(dpkg-query -W -f='${Architecture}' libcap2)" = 'amd64'; \
    test "$(dpkg-query -W -f='${Version}' libcap2)" = '1:2.75-10+deb13u1'; \
    test -z "$(dpkg --audit)"; \
    rm -f /tmp/libcap2.deb /var/log/dpkg.log

# ---------- Layer-cached Python dependency install ----------
# Copy only pyproject.toml + uv.lock so the Python dep resolve + wheel
# download + native-extension compile layer is cached unless those inputs
# change.  Before this split the Python install sat after `COPY . .`, so
# every source-only commit re-did ~4-5 min of dep work on cold builds.
#
# README.md is referenced by pyproject.toml's `readme =` field, but it's
# excluded from the build context by .dockerignore's `*.md`.  uv's build
# frontend stats the readme path during dep resolution, so we `touch` an
# empty placeholder — the real README is restored by `COPY . .` below.
#
# `uv sync --frozen --no-install-project --extra all --extra messaging`
# installs the deps reachable through the composite `[all]` extra
# (handpicked set intended for the production image — excludes `[dev]`),
# plus gateway messaging adapters that should work in the published image
# without a first-boot lazy install.  We do NOT use `--all-extras`:
# that would pull in `[rl]` (atroposlib + tinker + torch + wandb from
# git), `[yc-bench]` (another git dep), and `[termux-all]` (Android
# redundancy), none of which belong in the published container.
#
# Provider packages (anthropic, bedrock, azure-identity) are included
# so Docker users can use these providers without requiring runtime
# lazy-install access to PyPI (often blocked in containerized envs).
#
# The hindsight memory provider's client (hindsight-client) is baked in
# for the same reason: it lazy-installs into /opt/hermes/.venv at first
# use, which lives inside the (immutable) image layer rather than the
# governed runtime-state bind mount, so it is lost on every container recreate /
# image update and recall/retain then fails with
# `ModuleNotFoundError: No module named 'hindsight_client'` (#38128).
#
# The Matrix gateway's deps ([matrix] extra) are baked in because
# python-olm (transitive via mautrix[encryption]) builds from source on
# Python/image combinations without usable wheels.  The Docker image is
# Linux-only, so keeping the native libolm/build-toolchain packages here
# avoids the cross-platform failures that kept [matrix] out of [all]
# while still making Matrix work in the published container. Fixes #30399.
#
# The editable link is created after the source copy below.
COPY pyproject.toml uv.lock ./
RUN touch ./README.md
RUN uv sync --frozen --no-install-project --extra all --extra messaging --extra anthropic --extra bedrock --extra azure-identity --extra hindsight --extra matrix

# ---------- Frontend build (cached independently from Python source) ----------
# Copy only the frontend source trees first so that Python-only changes don't
# invalidate the (relatively slow) web + ui-tui build layer.
COPY web/ web/
COPY ui-tui/ ui-tui/
COPY apps/shared/ apps/shared/
RUN cd web && npm run build && \
    cd ../ui-tui && npm run build

# ---------- Source code ----------
# .dockerignore excludes node_modules, so the installs above survive.
# --link decouples this layer from parents for cache purposes; --chmod bakes
# the final read-only permissions at copy time so we skip the separate
# `chmod -R` pass that previously walked ~30k files across the venv +
# node_modules + source (21s amd64 / 222s arm64 — #49113).  `a+rX,go-w`
# gives the non-root hermes user read + traverse but no write; root retains
# write so the build steps below don't need chmod u+w dances.
COPY --link --chmod=a+rX,go-w . .

# ---------- Permissions ----------
# Link hermes-agent itself (editable). Deps are already installed in the
# cached layer above; `--no-deps` makes this a fast egg-link creation with no
# resolution or downloads.
RUN uv pip install --no-cache-dir --no-deps -e "."

# Wire the exec shim and install-method stamp.  Files under /opt/hermes are
# already root-owned (COPY, uv sync, npm install all run as root) and
# read-only for the hermes user (go-w from the --chmod above).

USER root
RUN mkdir -p /opt/hermes/bin && \
    cp /opt/hermes/docker/hermes-exec-shim.sh /opt/hermes/bin/hermes && \
    chmod 0755 /opt/hermes/bin/hermes && \
    printf 'docker\n' > /opt/hermes/.install_method
# The ``.install_method`` stamp is baked next to the running code (the install
# tree), NOT into $HERMES_HOME. $HERMES_HOME (/var/lib/hermes) is a private data
# volume that is commonly bind-mounted from the host and even shared with a
# host-side Desktop/CLI install; stamping it at boot used to clobber that
# host install's marker and wrongly block its ``hermes update``. A code-scoped
# stamp is read first by detect_install_method() and is immune to the share.
# Start as root so the s6-overlay stage2 hook can usermod/groupmod and chown
# the data volume. Each supervised service then drops to the hermes user via
# `s6-setuidgid hermes` in its run script. If HERMES_UID is unset, services
# run as the default hermes user (UID 10000).

# ---------- Bake build-time git revision ----------
# .dockerignore excludes .git, so `git rev-parse HEAD` from inside the
# container always returns nothing — meaning `hermes dump` reports
# "(unknown)" and the startup banner drops its `· upstream <sha>` suffix.
# That makes support triage from container bug reports impossible:
# we can't tell which commit the user is actually running.
#
# Fix: write the commit SHA passed via the HERMES_GIT_SHA build-arg to
# /opt/hermes/.hermes_build_sha at build time, and have
# hermes_cli/build_info.py read it at runtime.  Both `hermes dump` and
# banner.get_git_banner_state() try the baked SHA first, then fall back
# to live `git rev-parse` for source installs (unchanged behaviour).
#
# The arg is optional — local `docker build` without --build-arg simply
# omits the file, and the runtime falls back to live-git lookup.  CI
# (.github/workflows/docker.yml) passes ${{ github.sha }} so
# every published image has it.
ARG HERMES_GIT_SHA=
RUN if [ -n "${HERMES_GIT_SHA}" ]; then \
        printf '%s\n' "${HERMES_GIT_SHA}" > /opt/hermes/.hermes_build_sha; \
    fi

# ---------- s6-overlay service wiring ----------
# Static services declared at build time: main-hermes + dashboard.
# Per-profile gateway services are registered dynamically at runtime by
# the profile create/delete hooks (Phase 4); they live under
# /run/service/ (tmpfs) and are reconciled on container restart by
# /etc/cont-init.d/02-reconcile-profiles (Phase 4 Task 4.0).
COPY docker/s6-rc.d/ /etc/s6-overlay/s6-rc.d/

# stage2-hook handles UID/GID remap, volume chown, config seeding,
# skills sync — all the work the old entrypoint.sh did before
# `exec hermes`. Wired in as cont-init.d/01- so it
# runs before user services start.
#
# 02-reconcile-profiles re-creates per-profile gateway s6 service
# slots from $HERMES_HOME/profiles/<name>/ after a container restart
# (the /run/service/ scandir is tmpfs and wiped on restart). Phase 4.
RUN mkdir -p /etc/cont-init.d && \
    printf '#!/command/with-contenv sh\nexec /opt/hermes/docker/stage2-hook.sh\n' \
        > /etc/cont-init.d/01-hermes-setup && \
    chmod +x /etc/cont-init.d/01-hermes-setup
COPY --chmod=0755 docker/cont-init.d/015-supervise-perms /etc/cont-init.d/015-supervise-perms
COPY --chmod=0755 docker/cont-init.d/02-reconcile-profiles /etc/cont-init.d/02-reconcile-profiles

# ---------- Runtime ----------
ENV HERMES_WEB_DIST=/opt/hermes/hermes_cli/web_dist
# Point the TUI launcher at the prebuilt bundle baked at build time (Layer 8:
# `ui-tui && npm run build`). This makes _make_tui_argv take the prebuilt-bundle
# fast path (`node --expose-gc /opt/hermes/ui-tui/dist/entry.js`) and skip the
# _tui_need_npm_install / runtime `npm install` branch entirely — exactly the
# nix/packaged-release path the launcher was designed for.
#
# Why this is required (not just an optimization): the root package-lock.json
# describes the WHOLE monorepo workspace set (root + web + ui-tui + apps/*),
# but the image only installs root/web/ui-tui (apps/* — the desktop app — is
# never `npm install`ed here). So the actualized node_modules permanently
# disagrees with the canonical lock, _tui_need_npm_install() returns True on
# every launch, and the runtime `npm install` it triggers (a) can never
# converge against the partial monorepo and (b) races itself across concurrent
# embedded-chat (/api/pty) connections → ENOTEMPTY → the chat tab dies with a
# 502 / "[session ended]". Pointing at the prebuilt bundle sidesteps the whole
# check. (A separate launcher hardening is tracked independently.)
ENV HERMES_TUI_DIR=/opt/hermes/ui-tui
ENV HERMES_HOME=/var/lib/hermes
ENV HERMES_WRITE_SAFE_ROOT=/var/lib/hermes:/workspaces
ENV HERMES_DISABLE_LAZY_INSTALLS=1
# The governed runtime never installs code into mutable employee state. An
# optional backend must be baked into a reviewed image or supplied through a
# separately qualified broker/extension image.

# `docker exec` privilege-drop shim. When operators run
# `docker exec <c> hermes ...` they default to root, and any file the
# command writes under $HERMES_HOME (auth.json, .env, config.yaml) ends
# up root-owned and unreadable to the supervised gateway (UID 10000).
# The shim lives at /opt/hermes/bin/hermes, sits earliest on PATH, and
# transparently re-exec's the real venv binary via `s6-setuidgid hermes`
# when invoked as root. Non-root callers (supervised processes,
# `--user hermes`, etc.) hit the short-circuit path with no overhead.
# Recursion is impossible because the shim exec's the venv binary by
# absolute path (/opt/hermes/.venv/bin/hermes). See the shim source for
# the opt-out env var (HERMES_DOCKER_EXEC_AS_ROOT=1).

# Pre-s6 entrypoint.sh did `source .venv/bin/activate` which exported
# the venv bin onto PATH; Architecture B's main-wrapper.sh does the
# same for the container's main process, but `docker exec` and our
# cont-init.d scripts don't pass through the wrapper. Expose the venv
# bin globally so `docker exec <container> hermes ...` and any
# subprocess that doesn't activate the venv first still find hermes.
#
# /opt/hermes/bin is prepended ahead of the venv so the privilege-drop
# shim wins PATH resolution. The shim's last act is to exec the venv
# binary by absolute path, so this PATH ordering is transparent to
# every other consumer.
ENV PATH="/opt/hermes/bin:/opt/hermes/.venv/bin:${PATH}"

# s6-overlay's /init is PID 1. It sets up the supervision tree, runs
# /etc/cont-init.d/* (our stage2 hook), starts s6-rc services
# declared in /etc/s6-overlay/s6-rc.d/, then exec's its remaining
# argv as the container's "main program" with stdin/stdout/stderr
# inherited (this is what makes interactive --tui work). When the
# main program exits, /init begins stage 3 shutdown and the container
# exits with the program's exit code. Replaces tini — see Phase 2 of
# docs/plans/2026-05-07-s6-overlay-dynamic-subagent-gateways.md.
#
# We use the ENTRYPOINT+CMD split rather than CMD alone so the
# wrapper is prepended to user-supplied args automatically:
#
#   docker run <image>                  → /init main-wrapper.sh   (CMD default)
#   docker run <image> chat -q "hi"     → /init main-wrapper.sh chat -q hi
#   docker run <image> sleep infinity   → /init main-wrapper.sh sleep infinity
#   docker run <image> --tui            → /init main-wrapper.sh --tui
#
# main-wrapper.sh handles arg routing (bare-exec vs. hermes
# subcommand vs. no-args), drops to the hermes user via s6-setuidgid,
# and exec's the final program so its exit code becomes the container
# exit code. Without the wrapper-as-ENTRYPOINT, leading-dash args
# like `--version` would be intercepted by /init's POSIX shell.
ENTRYPOINT [ "/init", "/opt/hermes/docker/main-wrapper.sh" ]
CMD [ ]

# ---------- Minimal production runtime ----------
# Build compilers, development headers, npm/corepack, Docker CLI, and SSH are
# intentionally confined to the build stage. The final stage installs only
# the explicitly supported Python, browser, media, Git-over-HTTPS, terminal,
# and encrypted-messaging runtime capabilities.
FROM debian:13.4@sha256:e2d08da6f42ef4b09b165d55528a12727aeed8240dc9edf888e3ec07e10ef9da AS runtime
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH
ARG DEBIAN_SNAPSHOT
ARG S6_OVERLAY_VERSION=3.2.3.0
ARG S6_OVERLAY_NOARCH_SHA256=b720f9d9340efc8bb07528b9743813c836e4b02f8693d90241f047998b4c53cf
ARG S6_OVERLAY_X86_64_SHA256=a93f02882c6ed46b21e7adb5c0add86154f01236c93cd82c7d682722e8840563
ARG S6_OVERLAY_AARCH64_SHA256=0952056ff913482163cc30e35b2e944b507ba1025d78f5becbb89367bf344581
ARG S6_OVERLAY_SYMLINKS_SHA256=a60dc5235de3ecbcf874b9c1f18d73263ab99b289b9329aa950e8729c4789f0e

RUN set -eu; \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*; \
    printf '%s\n' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/" \
        'Suites: trixie trixie-updates' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        'Check-Valid-Until: no' \
        '' \
        'Types: deb' \
        "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/" \
        'Suites: trixie-security' \
        'Components: main' \
        'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
        'Check-Valid-Until: no' \
        > /etc/apt/sources.list.d/debian-snapshot.sources; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils \
        python3 python-is-python3 python3-venv \
        procps git ripgrep ffmpeg libolm3 \
        xvfb fonts-noto-color-emoji fonts-unifont libfontconfig1 libfreetype6 \
        xfonts-scalable fonts-liberation fonts-ipafont-gothic fonts-wqy-zenhei \
        fonts-tlwg-loma-otf fonts-freefont-ttf \
        libasound2t64 libatk-bridge2.0-0t64 libatk1.0-0t64 \
        libatspi2.0-0t64 libcairo2 libcups2t64 libdbus-1-3 libdrm2 libgbm1 \
        libglib2.0-0t64 libnspr4 libnss3 libpango-1.0-0 libx11-6 libxcb1 \
        libxcomposite1 libxdamage1 libxext6 libxfixes3 libxkbcommon0 libxrandr2; \
    case "${TARGETARCH:-amd64}" in \
        amd64) s6_arch="x86_64"; s6_arch_sha="${S6_OVERLAY_X86_64_SHA256}" ;; \
        arm64) s6_arch="aarch64"; s6_arch_sha="${S6_OVERLAY_AARCH64_SHA256}" ;; \
        *) echo "Unsupported TARGETARCH=${TARGETARCH} for s6-overlay" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 3 -o /tmp/s6-overlay-noarch.tar.xz \
        "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz"; \
    curl -fsSL --retry 3 -o /tmp/s6-overlay-arch.tar.xz \
        "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${s6_arch}.tar.xz"; \
    curl -fsSL --retry 3 -o /tmp/s6-overlay-symlinks-noarch.tar.xz \
        "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-symlinks-noarch.tar.xz"; \
    { \
        printf '%s  %s\n' "${S6_OVERLAY_NOARCH_SHA256}" /tmp/s6-overlay-noarch.tar.xz; \
        printf '%s  %s\n' "${s6_arch_sha}" /tmp/s6-overlay-arch.tar.xz; \
        printf '%s  %s\n' "${S6_OVERLAY_SYMLINKS_SHA256}" /tmp/s6-overlay-symlinks-noarch.tar.xz; \
    } | sha256sum -c -; \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-arch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay-symlinks-noarch.tar.xz; \
    rm -f /tmp/s6-overlay-*.tar.xz; \
    ln -sf /init /usr/bin/tini; \
    apt-get purge -y curl xz-utils; \
    apt-get autoremove -y --purge; \
    rm -rf /var/lib/apt/lists/* /var/log/apt/*; \
    rm -f /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache

# Apply the checksum-locked libcap2 security update to the final runtime stage,
# not only to the disposable build stage.
ADD --checksum=sha256:f8db64b636eb3e4f805b3f5f62cc32b99beec92df49920a9c24d34902bba0ce9 https://snapshot.debian.org/file/9d57cee3a8050e82ebd1ba078b5767a321bbf5ad /tmp/libcap2-runtime.deb
RUN set -eu; \
    test "${TARGETARCH:-amd64}" = 'amd64'; \
    printf '%s  %s\n' 'f8db64b636eb3e4f805b3f5f62cc32b99beec92df49920a9c24d34902bba0ce9' /tmp/libcap2-runtime.deb | sha256sum -c -; \
    test "$(dpkg-deb -f /tmp/libcap2-runtime.deb Package)" = 'libcap2'; \
    test "$(dpkg-deb -f /tmp/libcap2-runtime.deb Architecture)" = 'amd64'; \
    test "$(dpkg-deb -f /tmp/libcap2-runtime.deb Version)" = '1:2.75-10+deb13u1'; \
    dpkg -i /tmp/libcap2-runtime.deb; \
    test "$(dpkg-query -W -f='${Version}' libcap2)" = '1:2.75-10+deb13u1'; \
    test -z "$(dpkg --audit)"; \
    rm -f /tmp/libcap2-runtime.deb /var/log/dpkg.log

RUN set -eu; \
    epoch_days=$((SOURCE_DATE_EPOCH / 86400)); \
    printf 'hermes:x:10000:10000::/var/lib/hermes:/bin/sh\n' >> /etc/passwd; \
    printf 'hermes:x:10000:\n' >> /etc/group; \
    printf 'hermes:!:%s:0:99999:7:::\n' "${epoch_days}" >> /etc/shadow; \
    printf 'hermes:!::\n' >> /etc/gshadow; \
    install -d -o 10000 -g 10000 -m 0755 /var/lib/hermes; \
    rm -f /var/log/lastlog /var/log/faillog

COPY --chmod=0755 --from=uv_source /usr/local/bin/uv /usr/local/bin/uvx /usr/local/bin/
COPY --chmod=0755 --from=node_source /usr/local/bin/node /usr/local/bin/
COPY --from=build /opt/hermes /opt/hermes

WORKDIR /opt/hermes

COPY docker/s6-rc.d/ /etc/s6-overlay/s6-rc.d/
RUN mkdir -p /etc/cont-init.d && \
    printf '#!/command/with-contenv sh\nexec /opt/hermes/docker/stage2-hook.sh\n' \
        > /etc/cont-init.d/01-hermes-setup && \
    chmod +x /etc/cont-init.d/01-hermes-setup
COPY --chmod=0755 docker/cont-init.d/015-supervise-perms /etc/cont-init.d/015-supervise-perms
COPY --chmod=0755 docker/cont-init.d/02-reconcile-profiles /etc/cont-init.d/02-reconcile-profiles

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/hermes/.playwright
ENV npm_config_install_links=false
ENV HERMES_WEB_DIST=/opt/hermes/hermes_cli/web_dist
ENV HERMES_TUI_DIR=/opt/hermes/ui-tui
ENV HERMES_HOME=/var/lib/hermes
ENV HERMES_WRITE_SAFE_ROOT=/var/lib/hermes:/workspaces
ENV HERMES_DISABLE_LAZY_INSTALLS=1
ENV PATH="/opt/hermes/bin:/opt/hermes/.venv/bin:${PATH}"

ENTRYPOINT [ "/init", "/opt/hermes/docker/main-wrapper.sh" ]
CMD [ ]
