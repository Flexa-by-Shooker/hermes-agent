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
    ):
        assert required in runtime


def test_playwright_install_and_runtime_dependencies_are_versioned() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    runtime = _final_runtime_stage()

    assert "npx --yes playwright@1.61.1 install chromium --only-shell" in text
    assert "npx playwright install --with-deps" not in text
    for library in (
        "libasound2t64",
        "libatk-bridge2.0-0t64",
        "libcups2t64",
        "libgbm1",
        "libnss3",
        "libxkbcommon0",
    ):
        assert library in runtime
