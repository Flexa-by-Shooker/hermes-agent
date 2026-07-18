"""Security contracts for the production container's final runtime stage."""

from pathlib import Path
import tomllib


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "Dockerfile"
PYPROJECT = REPO_ROOT / "pyproject.toml"
UV_LOCK = REPO_ROOT / "uv.lock"


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


def test_flexa_engine_direct_dependencies_are_pinned_in_the_shared_runtime_venv() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    dependencies = set(project["dependencies"])
    assert "typer==0.24.1" in dependencies
    assert "tzdata==2025.3" in dependencies
    assert not any(item.startswith("tzdata==") and ";" in item for item in dependencies)

    lock = tomllib.loads(UV_LOCK.read_text(encoding="utf-8"))
    hermes = next(package for package in lock["package"] if package["name"] == "hermes-agent")
    locked = {item["name"]: item for item in hermes["dependencies"]}
    assert locked["typer"] == {"name": "typer"}
    assert locked["tzdata"] == {"name": "tzdata"}


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
    assert text.count("/var/cache/ldconfig/aux-cache") >= 4
    assert text.count("epoch_days=$((SOURCE_DATE_EPOCH / 86400))") >= 2
    assert text.count("hermes:!:%s:0:99999:7:::") >= 2


def test_python_olm_uses_the_snapshot_binary_instead_of_a_local_source_build() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert "python3-olm libffi-dev libolm-dev" in text
    assert "--no-install-package python-olm" in text
    assert "cp -a /usr/lib/python3/dist-packages/_libolm.abi3.so" in text
    assert "cp -a /usr/lib/python3/dist-packages/olm" in text
    assert "python_olm-3.2.16.egg-info" in text
    assert 'importlib.metadata.version("python-olm") == "3.2.16"' in text


def test_editable_install_drops_uvs_builder_local_cache_metadata() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert "hermes_agent-*.dist-info" in text
    assert 'rm -f "${dist_info}/uv_cache.json"' in text
    assert "sed -i '\\|/uv_cache\\.json,|d' \"${dist_info}/RECORD\"" in text
    assert "! grep -F '/uv_cache.json,' \"${dist_info}/RECORD\"" in text
