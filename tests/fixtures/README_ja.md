# Schema v1 fixture

[English](README.md) | [日本語](README_ja.md)

このdirectoryでは、仕様から作った境界と、実装が出力した成果物を分けて管理する。

- `qk-v1/`は、`quality-keeper`が公開したvalidな`sais` fixtureのbyte単位のcopy。
  `SOURCE.json`にupstream commit、各fileのhash、2つの正本schemaのcanonical JSON
  hashを固定する
- `sais-v1-release-candidate/`は、実`sais` runnerとofflineの決定論engineから生成する。
  `0.3.0-dev`としてcompleted、incomplete、error成果物を収録する

合成した`qk` fixtureが規範的で実行可能な境界であり続ける。release-candidate fixtureは
現在のproducerがその境界へ到達することを証明するもので、手書きの例を置き換えない。

live LLMを使わずproducer fixtureを再生成・検証できる。

```bash
python tools/generate_schema_v1_fixtures.py
python tools/generate_schema_v1_fixtures.py --check
```

S5では生成versionを`0.3.0-dev`から`0.3.0`へ変更してから、fixtureを
`quality-keeper`へ引き渡す。
