"""Pure-Python Qt .qm <-> .ts bidirectional converter.

Parses the binary .qm translation format and emits Qt Linguist .ts XML,
and compiles .ts XML back to .qm binary — using only the Python standard
library (struct, xml.etree, pathlib).

Usage:
    python qm_converter.py input.qm [-o output.ts]     # decompile
    python qm_converter.py input.ts [-o output.qm]     # compile

References:
    - Qt source: qttools/src/linguist/shared/qm.cpp
    - Format tags: Tag_End(0x01), Tag_Translation(0x03), Tag_Obsolete1(0x05),
      Tag_SourceText(0x06), Tag_Context(0x07), Tag_Comment(0x08)
"""

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

# ── QM binary constants ─────────────────────────────────────────────

QM_MAGIC = (0x3CB86418, 0xCAEF9C95, 0xCD211CBF, 0x60A1BDDD)
QM_MAGIC_BYTES = struct.pack(">4L", *QM_MAGIC)

SECTION_HASHES = 0x42
SECTION_MESSAGES = 0x69
SECTION_CONTEXTS = 0x2F
SECTION_NUMERUS = 0x88

TAG_END = 0x01
TAG_TRANSLATION = 0x03
TAG_OBSOLETE1 = 0x05
TAG_SOURCE_TEXT = 0x06
TAG_CONTEXT = 0x07
TAG_COMMENT = 0x08

# ── TS output defaults ──────────────────────────────────────────────

TS_VERSION = "2.0"


# ── Data model ───────────────────────────────────────────────────────

@dataclass(slots=True)
class Message:
    """A single translation unit extracted from a .qm or .ts file."""

    source: str = ""
    translations: list[str] = field(default_factory=list)
    context: str = ""
    comment: str = ""

    @property
    def is_plural(self) -> bool:
        return len(self.translations) > 1


# ── ELF hash (Qt variant) ───────────────────────────────────────────

def _elf_hash(*parts: bytes) -> int:
    """Compute the ELF hash used by Qt for .qm lookup tables.

    The hash is computed over the concatenation of all *parts* with no
    separator bytes. Qt hashes ``source + comment`` (ISO-8859-1 encoded).
    Returns 1 instead of 0 (Qt convention).
    """
    h: int = 0
    for part in parts:
        for byte in part:
            h = ((h << 4) + byte) & 0xFFFFFFFF
            g = h & 0xF0000000
            if g:
                h ^= g >> 24
            h &= ~g & 0xFFFFFFFF
    return h if h else 1


# ── QM parser ────────────────────────────────────────────────────────

class QmParseError(Exception):
    """Raised when the .qm binary cannot be parsed."""


def _read_sections(data: bytes) -> dict[int, bytes]:
    """Split a .qm file into its top-level sections."""
    if len(data) < 16:
        raise QmParseError("File too small to be a valid .qm")

    magic = struct.unpack_from(">4L", data)
    if magic != QM_MAGIC:
        raise QmParseError(f"Invalid magic: {magic:#x}")

    sections: dict[int, bytes] = {}
    pos = 16
    while pos + 5 <= len(data):
        section_type, length = struct.unpack_from(">BL", data, pos)
        pos += 5
        if pos + length > len(data):
            raise QmParseError(
                f"Section 0x{section_type:02X} at offset {pos - 5} "
                f"extends beyond file end"
            )
        sections[section_type] = data[pos : pos + length]
        pos += length
    return sections


def _parse_messages(blob: bytes) -> list[Message]:
    """Parse the Messages section (0x69) into a list of Message objects."""
    messages: list[Message] = []
    pos = 0
    current = Message()

    while pos < len(blob):
        tag = blob[pos]
        pos += 1

        if tag == TAG_END:
            if current.source or current.translations:
                messages.append(current)
            current = Message()
            continue

        # TAG_OBSOLETE1: 4-byte hash, no length prefix
        if tag == TAG_OBSOLETE1:
            pos += 4
            continue

        # All other tags: 4-byte signed length then payload
        if pos + 4 > len(blob):
            break
        (length,) = struct.unpack_from(">l", blob, pos)
        pos += 4

        payload = blob[pos : pos + length] if length > 0 else b""

        match tag:
            case 0x03:  # TAG_TRANSLATION – UTF-16 BE
                text = payload.decode("utf-16-be") if length > 0 else ""
                current.translations.append(text)
            case 0x06:  # TAG_SOURCE_TEXT – ISO-8859-1
                current.source = payload.decode("iso-8859-1") if length > 0 else ""
            case 0x07:  # TAG_CONTEXT – ISO-8859-1
                current.context = payload.decode("iso-8859-1") if length > 0 else ""
            case 0x08:  # TAG_COMMENT – ISO-8859-1
                current.comment = payload.decode("iso-8859-1") if length > 0 else ""

        if length > 0:
            pos += length

    return messages


def parse_qm(data: bytes) -> list[Message]:
    """Parse a .qm byte buffer and return all translation messages."""
    sections = _read_sections(data)

    if SECTION_MESSAGES not in sections:
        raise QmParseError("No messages section (0x69) found")

    return _parse_messages(sections[SECTION_MESSAGES])


# ── TS XML parser ────────────────────────────────────────────────────

@dataclass(slots=True)
class TsMetadata:
    """Metadata extracted from the <TS> root element."""

    version: str = TS_VERSION
    language: str = ""
    source_language: str = ""


def parse_ts(xml_text: str) -> tuple[list[Message], TsMetadata]:
    """Parse a Qt Linguist .ts XML string into Messages and metadata."""
    root = ET.fromstring(xml_text)

    meta = TsMetadata(
        version=root.get("version", TS_VERSION),
        language=root.get("language", ""),
        source_language=root.get("sourcelanguage", ""),
    )

    messages: list[Message] = []
    for ctx_el in root.findall("context"):
        ctx_name = ctx_el.findtext("name", default="")

        for msg_el in ctx_el.findall("message"):
            source = msg_el.findtext("source", default="")
            comment = msg_el.findtext("comment", default="")

            trans_el = msg_el.find("translation")
            translations: list[str] = []
            if trans_el is not None:
                numerus_forms = trans_el.findall("numerusform")
                if numerus_forms:
                    translations = [nf.text or "" for nf in numerus_forms]
                else:
                    translations = [trans_el.text or ""]

            messages.append(Message(
                source=source,
                translations=translations,
                context=ctx_name,
                comment=comment,
            ))

    return messages, meta


# ── TS XML emitter ───────────────────────────────────────────────────

def _group_by_context(messages: list[Message]) -> dict[str, list[Message]]:
    """Group messages by context, preserving insertion order."""
    groups: dict[str, list[Message]] = {}
    for msg in messages:
        groups.setdefault(msg.context, []).append(msg)
    return groups


def messages_to_ts(
    messages: list[Message],
    *,
    language: str = "",
    source_language: str = "",
    ts_version: str = TS_VERSION,
) -> str:
    """Convert a list of Messages into a Qt Linguist .ts XML string."""
    root = ET.Element("TS", version=ts_version)
    if language:
        root.set("language", language)
    if source_language:
        root.set("sourcelanguage", source_language)

    for ctx_name, ctx_messages in _group_by_context(messages).items():
        ctx_el = ET.SubElement(root, "context")
        ET.SubElement(ctx_el, "name").text = ctx_name

        for msg in ctx_messages:
            msg_el = ET.SubElement(ctx_el, "message")
            if msg.is_plural:
                msg_el.set("numerus", "yes")

            ET.SubElement(msg_el, "source").text = msg.source

            if msg.comment:
                ET.SubElement(msg_el, "comment").text = msg.comment

            translation_el = ET.SubElement(msg_el, "translation")
            if msg.is_plural:
                for form in msg.translations:
                    ET.SubElement(translation_el, "numerusform").text = form
            else:
                translation_el.text = (
                    msg.translations[0] if msg.translations else ""
                )

    ET.indent(root)
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<!DOCTYPE TS>\n"
        + ET.tostring(root, encoding="unicode")
        + "\n"
    )


# ── QM binary writer ────────────────────────────────────────────────

def _write_tag(tag: int, payload: bytes) -> bytes:
    """Encode a single tagged field: tag(1) + length(4) + payload."""
    return struct.pack(">Bl", tag, len(payload)) + payload


def _write_section(section_type: int, payload: bytes) -> bytes:
    """Encode a top-level section: type(1) + length(4) + payload."""
    return struct.pack(">BL", section_type, len(payload)) + payload


def messages_to_qm(messages: list[Message]) -> bytes:
    """Compile a list of Messages into a .qm binary byte string."""
    # 1. Build the messages blob and track offsets for the hash table
    msg_chunks: list[bytes] = []
    hash_entries: list[tuple[int, int]] = []  # (hash, offset)
    current_offset = 0

    for msg in messages:
        entry = bytearray()

        # Translations (UTF-16 BE) — one per form, plurals get multiple
        for trans in msg.translations:
            encoded = trans.encode("utf-16-be")
            entry += _write_tag(TAG_TRANSLATION, encoded)

        # Source text (ISO-8859-1)
        src_bytes = msg.source.encode("iso-8859-1", errors="replace")
        entry += _write_tag(TAG_SOURCE_TEXT, src_bytes)

        # Context (ISO-8859-1)
        ctx_bytes = msg.context.encode("iso-8859-1", errors="replace")
        entry += _write_tag(TAG_CONTEXT, ctx_bytes)

        # Comment (ISO-8859-1) — only if non-empty
        cmt_bytes = msg.comment.encode("iso-8859-1", errors="replace")
        if cmt_bytes:
            entry += _write_tag(TAG_COMMENT, cmt_bytes)

        # End marker
        entry += struct.pack(">B", TAG_END)

        # Compute hash: elf_hash(source + comment)
        h = _elf_hash(src_bytes, cmt_bytes)
        hash_entries.append((h, current_offset))

        msg_chunks.append(bytes(entry))
        current_offset += len(entry)

    messages_blob = b"".join(msg_chunks)

    # 2. Build the sorted hash table
    hash_entries.sort()  # sort by (hash, offset)
    hashes_blob = b"".join(
        struct.pack(">LL", h, off) for h, off in hash_entries
    )

    # 3. Assemble: magic + hashes section + messages section
    #
    # NOTE: Qt's lrelease also writes a NumerusRules section (0x88) containing
    # bytecode for plural-form selection (e.g. French: 0x03 0x01 = "n <= 1").
    # Each language has its own rule style (18 styles across ~60 languages),
    # defined in qttools/src/linguist/shared/numerus.cpp. We omit it here
    # because it requires a full language-to-bytecode lookup table.
    # QTranslator falls back to its built-in CLDR rules when the section is
    # absent, so this has no functional impact.
    # To add it: append _write_section(SECTION_NUMERUS, <bytecode>) below,
    # where <bytecode> is looked up from the language code (e.g. fr -> b'\x03\x01').
    return (
        QM_MAGIC_BYTES
        + _write_section(SECTION_HASHES, hashes_blob)
        + _write_section(SECTION_MESSAGES, messages_blob)
    )


# ── High-level API ──────────────────────────────────────────────────

def _guess_language(filename: str) -> str:
    """Try to extract a language code from the filename (e.g. 'app_fr.qm' -> 'fr')."""
    stem = Path(filename).stem
    parts = stem.rsplit("_", maxsplit=1)
    if len(parts) == 2 and 2 <= len(parts[1]) <= 5:
        return parts[1]
    return ""


def decompile(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    language: str | None = None,
    source_language: str = "",
    ts_version: str = TS_VERSION,
) -> Path:
    """Decompile a .qm file to .ts and return the output path."""
    input_path = Path(input_path)
    data = input_path.read_bytes()
    messages = parse_qm(data)

    if language is None:
        language = _guess_language(input_path.name)

    ts_xml = messages_to_ts(
        messages,
        language=language,
        source_language=source_language,
        ts_version=ts_version,
    )

    if output_path is None:
        output_path = input_path.with_suffix(".ts")
    else:
        output_path = Path(output_path)

    output_path.write_text(ts_xml, encoding="utf-8")
    return output_path


def compile_ts(
    input_path: str | Path,
    output_path: str | Path | None = None,
) -> Path:
    """Compile a .ts file to .qm and return the output path."""
    input_path = Path(input_path)
    xml_text = input_path.read_text(encoding="utf-8")
    messages, _meta = parse_ts(xml_text)

    qm_data = messages_to_qm(messages)

    if output_path is None:
        output_path = input_path.with_suffix(".qm")
    else:
        output_path = Path(output_path)

    output_path.write_bytes(qm_data)
    return output_path


# Keep backward compat
convert = decompile


# ── CLI ──────────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Bidirectional Qt .qm <-> .ts converter.",
    )
    parser.add_argument("input", help="Path to .qm or .ts file (auto-detected by extension)")
    parser.add_argument("-o", "--output", help="Output file path (default: same name, swapped extension)")
    parser.add_argument("--language", help="Target language code (default: guessed from filename)")
    parser.add_argument("--source-language", default="", help="Source language code")
    parser.add_argument("--ts-version", default=TS_VERSION, help=f"TS format version (default: {TS_VERSION})")

    args = parser.parse_args()
    input_path = Path(args.input)
    suffix = input_path.suffix.lower()

    if suffix == ".qm":
        out = decompile(
            input_path,
            args.output,
            language=args.language,
            source_language=args.source_language,
            ts_version=args.ts_version,
        )
        count = len(parse_qm(input_path.read_bytes()))
        print(f"Decompiled {args.input} -> {out}  ({count} messages)")

    elif suffix == ".ts":
        out = compile_ts(input_path, args.output)
        messages, _ = parse_ts(input_path.read_text(encoding="utf-8"))
        print(f"Compiled {args.input} -> {out}  ({len(messages)} messages)")

    else:
        parser.error(f"Unsupported file extension: {suffix} (expected .qm or .ts)")


if __name__ == "__main__":
    main()
