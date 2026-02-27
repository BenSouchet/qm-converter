# QM Converter

### Python script to convert Qt QM files to TS files or vice-versa.

This repository provide the `qm_converter.py` script, that's a fast Python implementation to compile or decompile PM files.

## The File Format

The QM file format (`.qm`) is a compact binary format that the localized application uses in Qt apps. It provides extremely fast lookup for translations.
Application does not need QM files to run, but if they are available, the application detects them and uses them automatically.

With the Official Qt Linguist Tools you normally use the `lrelease` command line tool produces QM files out of TS files.

**BUT** if you are looking for a pure Python implementation to decompile/decode or generate compiled PM files you can use `qm_converter`.

## How to use

