# QM Converter

Pure-Python bidirectional converter between Qt `.qm` (compiled binary) and `.ts` (XML source) translation files.

No Qt installation or dependency required — uses only the Python standard library.

## The QM File Format

The `.qm` file format is a compact binary format used by Qt applications for fast translation lookups at runtime. It contains:

- A **16-byte magic header** identifying the file
- A **hash table** (ELF hash) for O(log n) translation lookups
- **Message entries** with source text (ISO-8859-1), translations (UTF-16 BE), context, and comments
- Optional sections for plural rules and context tables

Normally, Qt's `lrelease` tool compiles `.ts` files into `.qm`, and `lconvert` can decompile them back.
This script replaces both tools with a single pure-Python implementation.

## Requirements

- Python 3.10+ (uses `match`/`case` syntax and modern type hints)
- No external dependencies

## Usage

### Command Line

The conversion direction is auto-detected from the input file extension:

```bash
# Decompile .qm to .ts
python qm_converter.py translations_fr.qm

# Compile .ts to .qm
python qm_converter.py translations_fr.ts

# Specify output path
python qm_converter.py input.qm -o output.ts

# Set language metadata (for .qm -> .ts)
python qm_converter.py app_fr.qm --source-language en

# Set TS format version
python qm_converter.py input.qm --ts-version 2.1
```

### Full CLI Options

```
usage: qm_converter.py [-h] [-o OUTPUT] [--language LANGUAGE]
                        [--source-language SOURCE_LANGUAGE]
                        [--ts-version TS_VERSION]
                        input

positional arguments:
  input                 Path to .qm or .ts file (auto-detected by extension)

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output file path (default: same name, swapped extension)
  --language LANGUAGE   Target language code (default: guessed from filename)
  --source-language SOURCE_LANGUAGE
                        Source language code
  --ts-version TS_VERSION
                        TS format version (default: 2.0)
```

### As a Library

```python
from qm_converter import parse_qm, parse_ts, messages_to_ts, messages_to_qm, Message

# Decompile: .qm -> Message objects
messages = parse_qm(Path("app_fr.qm").read_bytes())

# Compile: Message objects -> .qm binary
qm_bytes = messages_to_qm(messages)

# Parse .ts XML -> Message objects + metadata
messages, meta = parse_ts(Path("app_fr.ts").read_text("utf-8"))

# Emit .ts XML from Message objects
xml_str = messages_to_ts(messages, language="fr", source_language="en")

# High-level one-call conversions
from qm_converter import decompile, compile_ts

decompile("app_fr.qm")                # -> app_fr.ts
compile_ts("app_fr.ts")               # -> app_fr.qm
```

## Features

- **Bidirectional**: `.qm` -> `.ts` and `.ts` -> `.qm`
- **Plural forms**: correctly handles `numerus="yes"` messages with multiple `<numerusform>` entries
- **Context & comments**: preserves context names and disambiguation comments
- **Language auto-detection**: guesses the language code from the filename (e.g. `app_fr.qm` -> `fr`)
- **Zero dependencies**: only uses `struct`, `xml.etree.ElementTree`, `pathlib`, and `dataclasses`

## Limitations

- **Message ordering**: when decompiling `.qm` -> `.ts`, message order within each context follows the `.qm` hash order, not the original source-code `tr()` call order. This has no functional impact.
- **NumerusRules section**: the `.qm` writer omits the optional NumerusRules bytecode section (plural-form selection rules). Qt falls back to its built-in CLDR rules when this section is absent.

## License

[MIT](LICENSE) - Copyright (c) 2026 Ben Souchet

## Author

Ben Souchet - [contact@bensouchet.dev](mailto:contact@bensouchet.dev)
