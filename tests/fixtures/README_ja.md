# Schema v1 fixture

[English](README.md) | [日本語](README_ja.md)

このdirectoryでは、仕様から作った境界と、実装が出力した成果物を分けて管理する。

- `qk-v1/`は、`quality-keeper`が公開したvalidな`sais` fixtureのbyte単位のcopy。
  `SOURCE.json`にupstream commit、各fileのhash、2つの正本schemaのcanonical JSON
  hashを固定する
- `sais-v1-0.3.0/`は、実`sais` runnerとofflineの決定論engineから生成する。
  downstreamの適合テスト用に`0.3.0`のcompleted、incomplete、error成果物を収録する

合成した`qk` fixtureが規範的で実行可能な境界であり続ける。version固定したproducer
fixtureはrelease実装がその境界へ到達することを証明するもので、手書きの例を
置き換えない。

live LLMを使わずproducer fixtureを再生成・検証できる。

```bash
python tools/generate_schema_v1_fixtures.py
python tools/generate_schema_v1_fixtures.py --check
```

`sais-v1-0.3.0/`配下のfileを、producer側の`quality-keeper`引き渡し元とする。
release tagによって不変になった後、そのsource commitをdownstream側へ記録する。
