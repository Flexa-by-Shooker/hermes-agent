"""Stdlib document-to-text extraction for ``read_file``.

Supports Jupyter notebooks, DOCX, and XLSX without adding hard dependencies.
Malformed documents raise :class:`ExtractionError`; callers can then fall back to
normal text/binary handling.
"""

from __future__ import annotations

import json
import io
import posixpath
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

__all__ = [
    "EXTRACTABLE_EXTENSIONS",
    "ExtractionError",
    "extract_document_bytes",
    "extract_document_text",
    "is_extractable_document",
]

EXTRACTABLE_EXTENSIONS = frozenset({".ipynb", ".docx", ".xlsx"})
MAX_XLSX_BYTES = 50 * 1024 * 1024
_MAX_ZIP_MEMBERS = 5000
_MAX_ZIP_MEMBER_BYTES = 20 * 1024 * 1024
_MAX_ZIP_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
_MAX_XLSX_ROWS_PER_SHEET = 5000
_MAX_XLSX_COLS = 256
_MAX_XLSX_SHEETS = 100
_MAX_XLSX_TOTAL_CELLS = 100_000
_MAX_XLSX_CELL_CHARS = 8192
_MAX_EXTRACTED_CHARS = 2 * 1024 * 1024

_NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_NS_S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"


class ExtractionError(Exception):
    """Raised when a supported-looking document cannot be rendered as text."""


def _extension(path: str) -> str:
    ext = Path(path).suffix.lower()
    return ext if ext in EXTRACTABLE_EXTENSIONS else ""


def is_extractable_document(path: str) -> bool:
    return bool(_extension(path))


def extract_document_text(path: str) -> str:
    ext = _extension(path)
    if ext == ".ipynb":
        return _extract_notebook(path)
    if ext == ".docx":
        return _extract_docx(path)
    if ext == ".xlsx":
        return _extract_xlsx(path)
    raise ExtractionError(f"Unsupported document type: {path!r}")


def extract_document_bytes(data: bytes, suffix: str) -> str:
    """Extract a supported document without materializing plaintext on disk."""

    if not isinstance(data, bytes):
        raise ExtractionError("Document payload must be bytes")
    normalized = str(suffix or "").lower()
    if normalized == ".ipynb":
        return _extract_notebook_bytes(data)
    if normalized == ".docx":
        return _extract_docx(io.BytesIO(data))
    if normalized == ".xlsx":
        return _extract_xlsx(io.BytesIO(data))
    raise ExtractionError(f"Unsupported document type: {normalized!r}")


def _source_text(source) -> str:
    if isinstance(source, str):
        return source
    if isinstance(source, list):
        return "".join(item for item in source if isinstance(item, str))
    return ""


def _extract_notebook(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            nb = json.load(fh)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ExtractionError(f"Not a valid notebook: {exc}") from exc
    return _render_notebook(nb)


def _extract_notebook_bytes(data: bytes) -> str:
    try:
        nb = json.loads(data.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ExtractionError(f"Not a valid notebook: {exc}") from exc
    return _render_notebook(nb)


def _render_notebook(nb) -> str:
    if not isinstance(nb, dict):
        raise ExtractionError("Notebook root is not an object")

    cells = nb.get("cells")
    if not isinstance(cells, list):
        cells = [
            cell
            for ws in nb.get("worksheets", [])
            if isinstance(ws, dict)
            for cell in ws.get("cells", [])
        ]
    if not cells:
        raise ExtractionError("Notebook contains no cells")

    counts = {"markdown": 0, "code": 0, "raw": 0}
    labels = {"markdown": "Markdown", "code": "Code", "raw": "Raw"}
    out: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict):
            continue
        typ = cell.get("cell_type")
        if typ not in labels:
            continue
        counts[typ] += 1
        suffix = f" {counts[typ]}" if typ != "raw" else ""
        out.extend((f"# ── {labels[typ]} cell{suffix} ──", _source_text(cell.get("source", "")).rstrip("\n"), ""))
    if not out:
        raise ExtractionError("Notebook contains no readable cells")
    return "\n".join(out).rstrip("\n") + "\n"


def _zip_xml(zf: zipfile.ZipFile, name: str) -> ET.Element:
    try:
        return ET.fromstring(zf.read(name))
    except KeyError as exc:
        raise ExtractionError(f"Missing {name}") from exc
    except ET.ParseError as exc:
        raise ExtractionError(f"Malformed XML in {name}: {exc}") from exc


def _validate_zip_budget(zf: zipfile.ZipFile) -> None:
    infos = zf.infolist()
    if len(infos) > _MAX_ZIP_MEMBERS:
        raise ExtractionError("Document archive contains too many members")
    total = 0
    for info in infos:
        if info.file_size < 0 or info.file_size > _MAX_ZIP_MEMBER_BYTES:
            raise ExtractionError("Document archive member is too large")
        total += info.file_size
        if total > _MAX_ZIP_UNCOMPRESSED_BYTES:
            raise ExtractionError("Document archive expands beyond the safe limit")


def _extract_docx(path) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            _validate_zip_budget(zf)
            root = _zip_xml(zf, "word/document.xml")
    except zipfile.BadZipFile as exc:
        raise ExtractionError(f"Not a valid DOCX: {exc}") from exc
    except OSError as exc:
        raise ExtractionError(str(exc)) from exc

    w = f"{{{_NS_W}}}"
    lines: list[str] = []
    for para in root.iter(f"{w}p"):
        buf: list[str] = []
        for node in para.iter():
            if node.tag == f"{w}t":
                buf.append(node.text or "")
            elif node.tag == f"{w}tab":
                buf.append("\t")
            elif node.tag in {f"{w}br", f"{w}cr"}:
                buf.append("\n")
        lines.extend("".join(buf).split("\n"))
    if not any(line.strip() for line in lines):
        raise ExtractionError("DOCX contains no extractable text")
    return "\n".join(lines).rstrip("\n") + "\n"


def _extract_xlsx(path) -> str:
    try:
        with zipfile.ZipFile(path) as zf:
            _validate_zip_budget(zf)
            names = set(zf.namelist())
            shared = _shared_strings(zf, names)
            sheets = _workbook_sheets(zf)
            rels = _workbook_rels(zf, names)
            out: list[str] = []
            output_chars = 0
            total_cells = 0
            visible_sheets = 0
            for name, state, rid in sheets:
                if state in {"hidden", "veryHidden"}:
                    continue
                visible_sheets += 1
                if visible_sheets > _MAX_XLSX_SHEETS:
                    raise ExtractionError("XLSX contains too many visible sheets")
                part = _sheet_part(rels.get(rid, ""))
                if part not in names:
                    continue
                try:
                    rows, sheet_cells = _sheet_rows(
                        zf.read(part),
                        shared,
                        cell_budget=_MAX_XLSX_TOTAL_CELLS - total_cells,
                    )
                except ET.ParseError:
                    continue
                total_cells += sheet_cells
                out.append(f"# ── Sheet: {name} ──")
                output_chars += len(out[-1]) + 1
                if output_chars > _MAX_EXTRACTED_CHARS:
                    raise ExtractionError("XLSX text exceeds the safe limit")
                for row in rows:
                    row_chars = sum(len(value) for value in row) + max(
                        len(row) - 1, 0
                    )
                    output_chars += row_chars + 1
                    if output_chars > _MAX_EXTRACTED_CHARS:
                        raise ExtractionError("XLSX text exceeds the safe limit")
                    out.append("\t".join(row))
                if not rows:
                    output_chars += len("(empty)") + 1
                    if output_chars > _MAX_EXTRACTED_CHARS:
                        raise ExtractionError("XLSX text exceeds the safe limit")
                    out.append("(empty)")
                out.append("")
    except zipfile.BadZipFile as exc:
        raise ExtractionError(f"Not a valid XLSX: {exc}") from exc
    except OSError as exc:
        raise ExtractionError(str(exc)) from exc

    if not out:
        raise ExtractionError("XLSX has no visible sheets with content")
    return "\n".join(out).rstrip("\n") + "\n"


def _shared_strings(zf: zipfile.ZipFile, names: set[str]) -> list[str]:
    if "xl/sharedStrings.xml" not in names:
        return []
    try:
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    except ET.ParseError:
        return []
    s = f"{{{_NS_S}}}"
    return ["".join(t.text or "" for t in item.iter(f"{s}t")) for item in root.iter(f"{s}si")]


def _workbook_sheets(zf: zipfile.ZipFile) -> list[tuple[str, str, str]]:
    root = _zip_xml(zf, "xl/workbook.xml")
    s, r = f"{{{_NS_S}}}", f"{{{_NS_REL}}}"
    return [
        (sheet.get("name", "Sheet"), sheet.get("state", "visible"), sheet.get(f"{r}id", ""))
        for sheet in root.iter(f"{s}sheet")
    ]


def _workbook_rels(zf: zipfile.ZipFile, names: set[str]) -> dict[str, str]:
    rels_path = "xl/_rels/workbook.xml.rels"
    if rels_path not in names:
        return {}
    try:
        root = ET.fromstring(zf.read(rels_path))
    except ET.ParseError:
        return {}
    rel_tag = f"{{{_NS_PKG_REL}}}Relationship"
    return {rel.get("Id", ""): rel.get("Target", "") for rel in root.iter(rel_tag) if rel.get("Id")}


def _sheet_part(target: str) -> str:
    target = target.lstrip("/")
    return posixpath.normpath(target if target.startswith("xl/") else f"xl/{target}")


def _col_index(ref: str) -> int:
    idx = 0
    for ch in ref:
        if not ch.isalpha():
            break
        idx = idx * 26 + ord(ch.upper()) - ord("A") + 1
    return max(idx - 1, 0)


def _sheet_rows(
    xml_bytes: bytes,
    shared: list[str],
    *,
    cell_budget: int,
) -> tuple[list[list[str]], int]:
    root = ET.fromstring(xml_bytes)
    s = f"{{{_NS_S}}}"
    rows: list[list[str]] = []
    cells_seen = 0
    for row in root.iter(f"{s}row"):
        if len(rows) >= _MAX_XLSX_ROWS_PER_SHEET:
            break
        cells: dict[int, str] = {}
        max_col = -1
        for cell in row.iter(f"{s}c"):
            col = _col_index(cell.get("r", "")) if cell.get("r") else max_col + 1
            if col >= _MAX_XLSX_COLS:
                continue
            cells_seen += 1
            if cells_seen > cell_budget:
                raise ExtractionError("XLSX contains too many cells")
            cell_value = _cell_value(cell, shared, s)
            if len(cell_value) > _MAX_XLSX_CELL_CHARS:
                raise ExtractionError("XLSX cell text exceeds the safe limit")
            cells[col] = cell_value
            max_col = max(max_col, col)
        rows.append([cells.get(i, "") for i in range(max_col + 1)] if max_col >= 0 else [])
    while rows and not any(value.strip() for value in rows[-1]):
        rows.pop()
    return rows, cells_seen


def _cell_value(cell: ET.Element, shared: list[str], s: str) -> str:
    value = cell.findtext(f"{s}v") or ""
    typ = cell.get("t", "")
    if typ == "s":
        try:
            return shared[int(value)]
        except (ValueError, IndexError):
            return ""
    if typ == "inlineStr":
        inline = cell.find(f"{s}is")
        return "" if inline is None else "".join(t.text or "" for t in inline.iter(f"{s}t"))
    if typ == "b":
        return "TRUE" if value.strip() in {"1", "true", "TRUE"} else "FALSE"
    if typ == "e":
        return value or "#ERROR"
    return value
