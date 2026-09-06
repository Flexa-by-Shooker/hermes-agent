"""UTF-8 file reads paginate by characters while reporting byte file size."""
import json

from tools import file_tools


def test_hebrew_file_roundtrip_uses_char_budget_and_line_continuation(tmp_path, monkeypatch):
    from tools.environments.local import LocalEnvironment
    from tools.file_operations import ShellFileOperations

    path = tmp_path / "knowledge.txt"
    lines = ["שלום עולם", "עוד שורה", "ידע נשמר", "סוף דבר"]
    original = ("\n".join(lines) + "\n").encode("utf-8")
    path.write_bytes(original)
    environment = LocalEnvironment(cwd=str(tmp_path), timeout=10)
    try:
        operations = ShellFileOperations(environment)
        monkeypatch.setattr(file_tools, "_get_file_ops", lambda task_id: operations)
        monkeypatch.setattr(file_tools, "_get_max_read_chars", lambda: 26)
        file_tools.reset_file_dedup()
        offset, recovered = 1, []
        while offset <= len(lines):
            result = json.loads(file_tools.read_file_tool(str(path), offset=offset, limit=100,
                                                         task_id="unicode-budget-fixture"))
            assert not result.get("error")
            content = result["content"]
            assert len(content) <= 26
            assert len(content.encode("utf-8")) > 26
            assert result["file_size"] == len(original)
            numbered = [line.split("|", 1) for line in content.splitlines()]
            assert [int(number.strip()) for number, _ in numbered] == list(range(offset, offset + len(numbered)))
            recovered.extend(text for _, text in numbered)
            if result["truncated"]:
                assert result["truncated_by"] == "chars"
                assert result["next_offset"] == offset + len(numbered)
                offset = result["next_offset"]
            else:
                break
        # The read formatter preserves the final newline as one empty numbered
        # line. Rejoining pages must reproduce the original UTF-8 bytes.
        assert "\n".join(recovered).encode("utf-8") == original
        assert path.read_bytes() == original
    finally:
        environment.cleanup()
        file_tools.reset_file_dedup()
