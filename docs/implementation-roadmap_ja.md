# 実装ロードマップ

[English](implementation-roadmap.md) | [日本語](implementation-roadmap_ja.md)

状態: 実装進行中・S0完了

最終更新: 2026-08-25

## 1. 目的と位置付け

本ロードマップは、3製品からなる品質ツール群における
`security-ai-scanner`（`sais`）の実装順序を説明する参考文書である。
製品仕様と、製品群の
[共通成果物連携仕様](https://github.com/elvezjp/quality-keeper/blob/main/docs/common-result-interchange-specification_ja.md)
を規範的な仕様とする。

外部から観測できる振る舞いは、実装に先立って仕様化する。スキーマ、fixture、
適合性テストによって、仕様を実行可能にする。

## 2. 製品群全体の実装順序

| 段階 | 成果物 | 主担当リポジトリ |
|---|---|---|
| 0 | 共通成果物連携仕様 | `quality-keeper` — 完了 |
| 1 | スキーマと適合性fixture | `quality-keeper` — 完了 |
| 2 | 最初のschema version 1 producer（`sais` 0.3.0） | `security-ai-scanner` |
| 3 | 最小native consumer検証 | `quality-keeper` |
| 4 | `cair`の縦実装 | `code-ai-reviewer` |
| 5 | ポリシーエンジンとレポートの完成 | `quality-keeper` |
| 6 | 3製品E2E検証 | 3リポジトリ |

この順序では、2番目のproducerを作る前に、一つの実producerと最小consumerを
接続する。共通連携仕様を早期に検証し、変化中の成果物形式を`cair`へコピーする
ことを避ける。

## 3. 本リポジトリの役割

`sais`は、すでにCLI、エンジン抽象、結果の正規化、SARIF出力、レポート、
テストを備えているため、native producerの参照実装とする。

目標milestoneは、**schema version 1に対応するsecurity-ai-scanner 0.3.0**である。
採用作業は
[Issue #20](https://github.com/elvezjp/security-ai-scanner/issues/20)
で追跡する。

このmilestoneが完了するまで、Issue #20を`README.md`の製品機能ロードマップより
優先する。Issue #3から#6で追跡するP0項目はschema version 1適合の後に続け、
明示的に優先順位を変更しない限り並行して進めない。

実装は、`quality-keeper`がschema version 1のスキーマと適合性fixtureを公開した
後に開始する。fixtureはconsumerから観測できる受入境界を定義する。本リポジトリ
では、オフラインテスト用にproducer側のcopyまたは生成した同等物を維持する。

## 4. 作業パッケージ

### S0. 仕様とリリース境界 — 完了

- 成果物の変更に先立って製品仕様を更新する。
- 公開済み0.2.0のnative artifact形式からの意図的な破壊的変更として、
  0.3.0を宣言する。
- 終了コードの意味は維持する。`0`はpass、`1`はlocal gate fail、`2`は実行エラー。
- `qk`を最終CI gateにする場合の標準的な`--fail-on none`運用を文書化する。

完了条件: 英語版と日本語版の仕様が同じ0.3.0の振る舞いを記述し、共通成果物
連携仕様を参照している。

### S1. 実行識別情報とnative model

- `schema_version`、UUID `run_id`、`generated_at`、`status`、`subject`を追加する。
- 解析対象がGitリポジトリの場合、完全なGit object IDを解決する。
- filesystem対象には、Git識別情報やdigestを捏造せず記録する。
- `summary.json`と`findings.json`へ同じ実行識別情報とsubject metadataを含める。
- 両成果物の機械可読スキーマを公開する。

完了条件: live LLMを呼ばず、completed、incomplete、errorのobjectがschema
version 1に適合する。

### S2. 成果物の完全性とアトミックな公開

- summary以外の各`outputs` path文字列を、`path`、`sha256`、`bytes`を持つ要素へ
  変更する。`summary.json`は完了マーカーであり、自身の最終byte列のdigestを
  自身に格納できないため、`outputs`から除外する。
- 実行開始前に古い`summary.json`を無効化する。
- 出力先と同じfilesystem上の一時ファイルへ成果物を書く。
- 最終成果物pathへアトミックに置き換える。
- 完了マーカーとして`summary.json`を最後に公開する。
- 一つの出力ディレクトリへの並行writerを防止するか、明示的に拒否する。

完了条件: 中断テストによって、古い成果物と新しい成果物が一つの完了runとして
誤認されないことを証明する。

### S3. 完了・中断・エラー時の振る舞い

- 解析が正常終了した場合だけ`status: completed`を出力する。
- token budget、maximum turn、その他の部分結果では`status: incomplete`を出力する。
- 未知の非nullな`stopped`理由も、すべてincompleteとして扱う。
- 出力ディレクトリを利用できる場合、best effortで`error` summaryを書き、
  終了コード`2`を維持する。
- 人が読む出力は英日対応とし、機械可読識別子は言語非依存にする。

完了条件: CLIとrunnerのテストが、仕様で許可するすべてのstatusと終了コードの
組合せを網羅する。

### S4. 適合性テストと回帰テスト

- 2つのnative artifact間で実行識別情報が一致することをテストする。
- hash、byte数、重要度別件数を再計算して検証する。
- 古いsummaryの無効化とアトミックな置換をテストする。
- clean Git、dirty Git、non-Git subjectをテストする。
- `qk`が公開する正本の手書き適合性fixtureに対して、生成した出力を検証する。
- 仕様が明示的に変更しない限り、既存のengine、parse、report、SARIF、MCP、
  notificationの振る舞いを維持する。

完了条件: producerの全offline conformance testがpassし、schema version 1の
実completed・incomplete fixtureを`qk`へ渡せる。

### S5. リリースと後続への引き渡し

- packageとruntime versionを0.3.0へ更新する。
- `README.md`、`README_ja.md`、changelog、仕様を同じreleaseで更新する。
- `cair`がOpenAI互換read-only engineと成果物基盤をコピーする最終source commitを
  記録する。
- completedとincompleteのfixtureを`quality-keeper`へ提供する。

完了条件: 0.3.0のrelease artifactと文書が一致し、後続のsource commitが不変の
ものとして記録されている。

## 5. 実装規律

- schema version 1適合と無関係な製品機能を同じ実装変更へ含めない。
- engine固有のimportは`engine/<name>.py`内に閉じる。
- unit testとconformance testはすべてofflineで実行し、live engine testは
  integration testとして明示する。
- schema version 1でlegacy 0.2.0の成果物形式を維持しない。
- 適合済み`sais`のsource commitを選定するまで、`cair`へのcode copyを開始しない。

## 6. 次段階への引き渡し

S5の後、`quality-keeper`は実際の`sais`出力に対する最小native consumer経路を
実装・検証する。その経路がpassした後にだけ、`code-ai-reviewer`は記録済みの
source commitから縦実装を開始する。
