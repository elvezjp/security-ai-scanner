# Schema v1 fixtures

[English](README.md) | [日本語](README_ja.md)

This directory separates the specification-derived boundary from artifacts
emitted by the implementation:

- `qk-v1/` is a byte-for-byte copy of the valid `sais` fixtures published by
  `quality-keeper`. `SOURCE.json` pins the upstream commit, file hashes, and
  canonical JSON hashes of the two authoritative schemas.
- `sais-v1-release-candidate/` is generated through the real `sais` runner and
  an offline deterministic engine. It contains completed, incomplete, and error
  artifacts labeled `0.3.0-dev`.

The synthetic `qk` fixtures remain the normative executable boundary. The
release-candidate fixtures prove that the current producer reaches that
boundary; they do not replace the hand-authored examples.

Regenerate or verify the producer fixtures without a live LLM:

```bash
python tools/generate_schema_v1_fixtures.py
python tools/generate_schema_v1_fixtures.py --check
```

S5 changes the generated version from `0.3.0-dev` to `0.3.0` before handing the
fixtures to `quality-keeper`.
