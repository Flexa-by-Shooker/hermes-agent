"""Security contracts for the production container's final runtime stage."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"


def _final_runtime_stage() -> str:
    text = DOCKERFILE.read_text(encoding="utf-8")
    lines = text.splitlines()
    starts = [
        index
        for index, line in enumerate(lines)
        if line.startswith("FROM ") and line.endswith(" AS runtime")
    ]
    assert len(starts) == 1, "Dockerfile must define exactly one named final runtime stage"
    return "\n".join(lines[starts[0] :])


def test_final_image_is_built_from_a_separate_minimal_runtime_stage() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    runtime = _final_runtime_stage()

    assert " AS build" in text
    assert "COPY --from=build /opt/hermes /opt/hermes" in runtime
    assert "COPY --chmod=0755 --from=node_source /usr/local/bin/node" in runtime
    assert "/usr/local/lib/node_modules/npm" not in runtime
    assert "/usr/local/lib/node_modules/corepack" not in runtime


def test_final_runtime_excludes_build_and_administrative_tools() -> None:
    runtime = _final_runtime_stage()
    forbidden_packages = (
        "cmake",
        "docker-cli",
        "g++",
        "gcc",
        "libffi-dev",
        "libolm-dev",
        "make",
        "openssh-client",
        "python3-dev",
    )
    for package in forbidden_packages:
        assert package not in runtime, f"{package} must not be present in the final stage"

    for required in (
        "ca-certificates",
        "ffmpeg",
        "git",
        "libolm3",
        "python3-venv",
        "ripgrep",
        "xvfb",
        "/tmp/libcap2-runtime.deb",
        "1:2.75-10+deb13u1",
    ):
        assert required in runtime


def test_playwright_install_and_runtime_dependencies_are_versioned() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    runtime = _final_runtime_stage()

    assert "npx playwright" not in text
    assert "npx --yes playwright" not in text
    assert "149.0.7827.55" in text
    assert "chromium_headless_shell-1228" in text
    assert "ffmpeg-1011" in text
    assert "410c9407d5de3fea80d9398666be06f2aa09154a3fa7b327dc254e336bb4c4b7" in text
    assert "ebc74fc5b94830176a3c2914ae96bd8bc7f6a91f4f33890230f84a172ee61ccc" in text
    assert text.count("INSTALLATION_COMPLETE") >= 2
    assert text.count("DEPENDENCIES_VALIDATED") >= 2
    for library in (
        "libasound2t64",
        "libatk-bridge2.0-0t64",
        "libcups2t64",
        "libgbm1",
        "libnss3",
        "libxkbcommon0",
    ):
        assert library in runtime


def test_remote_dependency_universe_and_frontend_are_immutable() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert text.startswith(
        "# syntax=docker/dockerfile:1.7@sha256:"
        "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
    )
    assert "ARG SOURCE_DATE_EPOCH=1783793773" in text
    assert "ARG DEBIAN_SNAPSHOT=20260718T000000Z" in text
    assert text.count("snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}") >= 2
    assert text.count("snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}") >= 2
    assert "Check-Valid-Until: no" in text
    assert "deb.debian.org" not in text


def test_generated_package_and_user_state_is_clock_independent() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert text.count("/var/log/apt/*") >= 2
    assert text.count("/var/log/dpkg.log") >= 2
    assert text.count("/var/cache/ldconfig/aux-cache") >= 2
    assert text.count("epoch_days=$((SOURCE_DATE_EPOCH / 86400))") >= 2
    assert text.count("$1 == \"hermes\" { $3 = epoch_days }") >= 2
