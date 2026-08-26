# security-ai-scanner

[English](https://github.com/elvezjp/security-ai-scanner/blob/main/README.md) | [日本語](https://github.com/elvezjp/security-ai-scanner/blob/main/README_ja.md)

[![Elvez](https://img.shields.io/badge/Elvez-Product-3F61A7?style=flat-square)](https://elvez.co.jp/)
[![IXV Ecosystem](https://img.shields.io/badge/IXV-Ecosystem-3F61A7?style=flat-square)](https://elvez.co.jp/ixv/)
[![PyPI version](https://img.shields.io/pypi/v/security-ai-scanner?style=flat-square)](https://pypi.org/project/security-ai-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Stars](https://img.shields.io/github/stars/elvezjp/security-ai-scanner?style=social)](https://github.com/elvezjp/security-ai-scanner/stargazers)

![security-ai-scanner 実行デモ](https://raw.githubusercontent.com/elvezjp/security-ai-scanner/main/docs/assets/demo.png)

ソースコードのセキュリティ脆弱性を、AI エージェントでスキャンするツールです。
LLM エージェントが読み取り専用ツールでリポジトリを読み、入力源から危険な処理
（シンク）までのデータフローを追跡・検証した上で、SARIF・JSON・Markdown
レポートとして脆弱性を報告します。

## 特徴

- **エージェント型解析**: AI エージェント自身がリポジトリを探索します。エントリポイントの列挙、信頼できない入力の追跡、報告前の妥当性検証までを一貫して行います
- **読み取り専用設計**: エージェントに許可されるのは Read / Glob / Grep のみ。シェル実行・書き込み・ネットワークツールはスキャン中は禁止されます
- **SARIF 2.1.0 出力**: GitHub Code Scanning や標準的な AppSec ツールにそのまま取り込めます
- **CI ゲート内蔵**: `--fail-on high` を指定すると、しきい値以上の所見がある場合に非ゼロで終了し、パイプラインを止められます
- **構造化された所見**: 結果は JSON Schema（重要度・確度・CWE・該当箇所・推奨対応）に準拠して生成されます。壊れやすいテキスト解析には依存しません
- **日英バイリンガルレポート**: 所見の説明と Markdown レポートは英語・日本語を選択できます（`--language ja`）
- **ローカルLLM対応**: コードを一切マシンの外に出さずにスキャン — 内蔵の `openai` エンジンで OpenAI 互換サーバー（vLLM・Ollama・LM Studio・llama.cpp）に直結、または既定の `claude` エンジンで Anthropic 互換エンドポイントに接続できます
- **エンジン非依存のコア**: スキャナ本体は薄いエンジンアダプタとだけ通信します。標準エンジンは Claude Agent SDK で、コアに手を入れずに他のバックエンドを追加できます

## ユースケース

- **リリース前監査**: 出荷前にフルスキャンを実行し、Markdown レポートをレビュー
- **CI セキュリティゲート**: 高重要度の所見が出たらプルリクエストのパイプラインを失敗させる
- **GitHub Code Scanning**: `findings.sarif` をアップロードして Security タブに所見を表示
- **トリアージ入力**: `findings.json` を自社の管理・チケットワークフローに連携

## ドキュメント

- [CHANGELOG_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CHANGELOG_ja.md) - 更新履歴
- [CONTRIBUTING_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CONTRIBUTING_ja.md) - コントリビューションガイド
- [SECURITY_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/SECURITY_ja.md) - セキュリティポリシー
- [spec_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/spec_ja.md) - 技術仕様書（[英語正本](https://github.com/elvezjp/security-ai-scanner/blob/main/spec.md)）
- [実装ロードマップ](https://github.com/elvezjp/security-ai-scanner/blob/main/docs/implementation-roadmap_ja.md) - 製品群全体の順序と0.3.0適合計画
- [ローカル LLM E2E 検証記録](https://github.com/elvezjp/security-ai-scanner/blob/main/docs/local-llm-e2e-verification.md) - 脆弱性を仕込んだフィクスチャでのローカルモデル実測結果
- [製品群の互換性とQ8検証根拠](https://github.com/elvezjp/quality-keeper/blob/main/docs/compatibility_ja.md) - privateな3製品対応matrixと最終gate scenario

## インストール

Python 3.11 以上が必要です。標準エンジンは
[Claude Agent SDK](https://pypi.org/project/claude-agent-sdk/) を使用します。
SDK に Claude Code CLI が同梱されているため、Node.js の個別インストールは不要です。

```bash
pip install security-ai-scanner
# または uv で
uv add security-ai-scanner
```

インストール後、`security-ai-scanner` コマンド（短縮エイリアス `sais`）が
`PATH` 上で使えるようになります。

### 認証

標準エンジンの認証は Claude Code と同じです。どちらか一方を行ってください。

```bash
# 方法1: Claude アカウントでサインイン
claude login

# 方法2: API キーを設定
export ANTHROPIC_API_KEY=sk-ant-...
```

## 使い方

```bash
security-ai-scanner scan path/to/repo
```

`./security-scan-results/` 配下に次のファイルが生成されます。

- `findings.json`: 重要度・確度・CWE・該当箇所・推奨対応を含む構造化所見
- `findings.sarif`: GitHub Code Scanning・SARIF ビューア向けの SARIF 2.1.0 ログ
- `report.md`: 人が読むための Markdown レポート
- `summary.json`: schema version 1の実行manifest兼完了マーカー

各成果物は一つの出力ディレクトリ内で安全に一括確定し、`summary.json`を最後に
確定します。`.sais.lock`により同時書き込みを拒否します。中断したprocessがlockを
残した場合は、実行中のscanがないことを確認してから削除してください。

0.3.0ではnative artifactのschema version 1を導入する。これは0.2.0からの意図的な
破壊的変更である。consumerは`schema_version`を検証し、0.2.0の`summary.json`や
`findings.json`をschema version 1として解釈してはならない。

終了コードは、`--fail-on` のしきい値以上の所見がなければ `0`、あれば `1`
（CI ゲート）、エラー時は `2` です。

output lock取得後の実行失敗では、可能な場合にschema version 1の
`status: "error"` summaryを確定します。`--json`指定時は終了コード2を維持したまま、
同じobjectをstdoutへ出力します。確定処理前のvalidation errorやlock取得失敗では
JSONを出力せず、既存成果物も変更しません。

### よく使う例

**日本語レポートでスキャン:**
```bash
sais scan path/to/repo --language ja
```

**CI ゲートとして使う（critical のみでビルドを失敗させる）:**
```bash
sais scan . --fail-on critical
```

**SARIF派生成果物を任意のディレクトリへ出力:**
```bash
sais scan . --format sarif -o ./out
```

nativeの`findings.json`と`summary.json`は常に出力する。`--format`は追加の
派生成果物を選択する。

**スキャナに追加コンテキストを渡す（スコープや脅威モデルのメモ）:**
```bash
sais scan . --context "インターネット公開の Flask API。api/ ディレクトリを重点的に。"
```

**エージェントの進行状況を表示:**
```bash
sais scan . -v
```

## ローカルLLMでスキャンする

自社ホストのエンドポイントに接続する経路は2つあります。どちらでも
ホスト型 API には何も送信されません。

### OpenAI 互換サーバー（`--engine openai`）

自社ホスト推論の事実上の標準は OpenAI 互換 API です — vLLM・Ollama・
LM Studio・llama.cpp server・社内ゲートウェイ。`openai` エンジンは
内蔵の最小エージェントループでこれらに直結します。ツールは本パッケージが
Python で実装する `read_file` / `glob` / `grep` の3つだけで、スキャン
ルートにサンドボックスされます。つまり read-only は構成上の保証です —
ループ内にシェル・書き込み・ネットワークのツールは存在せず、外部の
エージェントハーネスも介在しません。

```bash
sais scan ./repo \
  --engine openai \
  --base-url http://127.0.0.1:11434/v1 \
  --model qwen2.5-coder:32b
```

`--model` は必須です（環境変数 `SAIS_MODEL` でも指定可）。意図的に既定値を
持ちません。model フィールドを無視するサーバーがあり、推測の既定値では
スキャン出力に誤ったモデル名が記録されてしまうためです。未指定エラー時は
`GET /v1/models` からサーバーが実際に提供するモデル名を候補として表示します。

`--max-tokens N` でスキャン全体のトークン予算を設定できます。予算に達すると
ツール呼び出しを止め、それまでの所見を保持したまま `summary.json` に
`"stopped": "budget_exceeded"` を記録します。予算停止で所見ゼロの場合も
終了コードは 0 になり、モデルの文章サマリは途中打ち切りを認めないことが
あります。CI でクリーン判定を信じる前に `stopped` が null であることも
確認してください。また、レスポンスに `usage` を含めないサーバでは
`total_tokens` が過少計上され、予算の強制が弱まります。

### Anthropic 互換サーバー（`--engine claude`・既定）

`--base-url` に自社ホストの Anthropic 互換エンドポイントを指定します。
この経路では Claude Agent SDK 同梱の Claude Code CLI がエージェント
ハーネスとしてローカルで動作し、推論エンドポイントだけが切り替わる点に
注意してください。

```bash
sais scan ./repo \
  --base-url http://127.0.0.1:8000 \
  --auth-token local \
  --model your-local-model
```

ローカルサーバーは通常ひとつのモデルしか提供しないため、スキャナは
エージェントが使うモデルスロット（opus / sonnet / haiku / サブエージェント）
をすべて `--model` に固定します。また、ホスト型 API の認証情報が優先されて
ローカルに繋がらなくなるのを防ぐため、子プロセスの環境から認証情報を
クリアします。

### 両エンジン共通

スキャナはリポジトリの内容を `--base-url` で指定した先へ送信します。
この URL は信頼するインフラとして扱い、自分の管理下にない
エンドポイントを指定しないでください。

エンドポイントが本物の認証情報を必要とする場合は、`--auth-token` では
なく環境変数 `SAIS_AUTH_TOKEN` の利用を推奨します。コマンドライン引数は
プロセス一覧・シェル履歴・CI ログに露出するためです。

スキーマ制約付きの構造化出力は、`--base-url` 指定時は**自動的にオフ**に
なります（ローカルサーバーの対応がまちまちなため）。代わりに
フェンス付き JSON ブロックでの出力を要求して解析します。対応している
サーバーであれば（`openai` エンジンでは `response_format: json_schema`）
`--structured-output` で有効化できます。

### コンテキスト長に収まるようスコープを絞る

**実運用でいちばん効いてくる制約です。** エージェントは作業しながら
ソースをコンテキストに読み込むため、リポジトリ全体を対象にすると
コンテキスト長の小さいエンドポイントではスキャン途中で上限に達します。
当社の検証では、Python 43ファイルのリポジトリを 100K トークンの
ローカルエンドポイントに対してスキャンすると約 98.5K で失敗しましたが、
アプリケーションパッケージ（`backend/app`・25ファイル）に絞った同じ
スキャンは正常に完走しました。

ローカルエンドポイントを使う場合は、リポジトリのルートではなく
コンポーネント単位を対象にしてください。セキュリティ上重要なコードは
通常ひとつのパッケージに集まっているため、実務上の支障は多くありません。

### 品質の目安

#### ホスト型 vs ローカル（`claude` エンジンでの測定）

脆弱性が既知で、かつ人手で確認済みのリポジトリをスキャンして測定しました。

| | ホスト型 API | ローカルエンドポイント |
|---|---|---|
| 既知の脆弱性の検出 | 3件中3件 | 3件中2件（ファイル・行番号まで一致） |
| 追加で見つけた実在の問題 | — | CORS ワイルドカードと認証情報の同時許可、リクエスト内容を出力するデバッグ文、ブランチ参照の依存 |
| 誤検出 | 観測されず | 観測されず |
| 深刻度の一貫性 | 一貫している | ばらつきあり（パストラバーサルを低めに、認証欠如を高めに評価） |
| 速度 | 数分 | おおむね一桁遅い |

ローカルモデルはキーワード照合ではなく、実際にデータフローを追跡し、
正確な行番号を挙げる「レビュアー」として機能しました。ホスト型が
見逃した実在の問題も検出しています。弱いのは**その所見がどれだけ
重要かの判断**なので、深刻度はそのまま順位として使うのではなく、
トリアージの出発点として扱ってください。

実用的な使い分けとしては、**機密性が高いコードのスクリーニングは
ローカル、リリース前監査や深刻度の順位そのものが判断を左右する場面は
ホスト型**が現実的です。

#### モデル比較（`openai` エンジン）

2種類のサーバー実装に対する4回の実機スキャン。対象は脆弱性を4件
（コマンドインジェクション・SQL インジェクション・パストラバーサル・
ハードコード鍵）仕込んだ4ファイルの Flask フィクスチャです。

| モデル（サーバー） | 仕込んだ脆弱性の検出 | 誤検出 | 時間 / トークン |
|---|---|---|---|
| Muse-Glimmer-30B GGUF（llama.cpp） | 4 / 4 | なし | 83秒 / 15,310 |
| qwen3.8:27b（Ollama） | 4 / 4 | なし | 131秒 / 10,759 |
| ornith-1.5:35b（Ollama） | 4 / 4 | なし | 25秒 / 6,887 |
| qwen2.5-coder:7b（Ollama） | **0 / 4** — ツールループを回せない | — | 0.5秒 / 1,300 |

合格したモデルはいずれも、フィクスチャに仕込んでいない実在の問題
（`DEBUG = True`）も併せて指摘しました。**十分な能力のモデル同士では
検出結果は一様で、差が出たのは深刻度の較正と速度だけ**です。律速に
なるのはサーバーやトランスポートではなくモデルの能力なので、
おおむね 27B 級以上を推奨します。ツール呼び出しを正しく出力できない
モデルは、何も読まないまま即座に「クリーン」と回答しますが、
エンジンはこれをクリーンなスキャンとして扱わず、エラー（終了コード 2）
として拒否します。

手法・各ランの所見・失敗の分析は
[docs/local-llm-e2e-verification.md](https://github.com/elvezjp/security-ai-scanner/blob/main/docs/local-llm-e2e-verification.md)
を参照してください。

> **注意**: サーバーが同時に1リクエストしか処理できない場合は、
> 並列ではなく直列でスキャンを実行してください。

## ライブラリとして使う

`security-ai-scanner` は Python ライブラリとしても利用できます。

```python
from pathlib import Path
from security_ai_scanner import ScanConfig, run_scan

result = run_scan(ScanConfig(target=Path("path/to/repo"), language="ja"))

for finding in result.output.findings:
    print(finding.severity, finding.file, finding.title)

print(result.gate_failed)   # しきい値以上の所見があれば True
```

CLI オプションは `ScanConfig` のフィールドと 1:1 に対応します
（例: `fail_on="critical"`、`formats=("sarif",)`）。

### ソースから

```bash
git clone https://github.com/elvezjp/security-ai-scanner.git
cd security-ai-scanner
uv sync
```

開発環境の詳細は [CONTRIBUTING_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CONTRIBUTING_ja.md) を参照してください。

## 主要オプション

| オプション | 既定値 | 説明 |
|--------|---------|-------------|
| `-o`, `--output-dir` | `./security-scan-results` | 出力ディレクトリ |
| `--engine` | `claude` | AI エンジン: `claude`（Claude Agent SDK）/ `openai`（OpenAI 互換エンドポイント向け内蔵ループ） |
| `--model` | `claude` は既定あり / `openai` は必須 | エンジンに渡すモデル指定（環境変数 `SAIS_MODEL` でも可） |
| `--base-url` | ホスト型 API | 自社ホストのエンドポイント: `claude` は Anthropic 互換 / `openai` は OpenAI 互換 |
| `--auth-token` | 環境変数 `SAIS_AUTH_TOKEN` | `--base-url` 用の認証トークン（本物の認証情報は環境変数を推奨） |
| `--structured-output` | 自動 | 構造化出力の強制切替（無効化は `--no-structured-output`） |
| `--language` | `en` | 所見・レポートの言語（`en` / `ja`） |
| `--context` | - | スキャンへの追加コンテキスト |
| `--fail-on` | `high` | CI ゲートのしきい値（`critical`/`high`/`medium`/`low`/`info`/`none`） |
| `--format` | 全形式 | 追加の派生成果物。繰り返し指定可（`json`/`sarif`/`markdown`）。native JSONは常に出力 |
| `--max-turns` | `100` | エージェントの最大ターン数 |
| `--max-tokens` | 上限なし | スキャン全体のトークン予算（openai エンジン）。到達時は部分所見を保持して早期終了 |
| `-v`, `--verbose` | false | エージェントの進行状況を stderr に表示 |
| `--json` | false | 機械可読サマリを stdout に出力（エージェント・スクリプト向け） |
| `--notify-webhook` | - | 完了・失敗時にサマリを POST する webhook URL（`SAIS_NOTIFY_WEBHOOK` でも可） |
| `--notify-format` | `generic` | ペイロード形式：`generic`（サマリ JSON）/ `discord` / `slack` |

## AI エージェントから使う

`sais` はコーディングエージェント（Claude Code・Codex・Cursor・VS Code の
エージェント等）から扱いやすいよう設計されています：安定した終了コード、
常に書き出される `summary.json`、stdout に1行 JSON を返す `--json`。
エージェント向けの仕様は [AGENTS.md](https://github.com/elvezjp/security-ai-scanner/blob/main/AGENTS.md) を参照してください。

### Claude Code スキル

[`skills/sais-scan/SKILL.md`](https://github.com/elvezjp/security-ai-scanner/blob/main/skills/sais-scan/SKILL.md) は Claude Code
（および互換エージェント）向けのスキルです。スキルディレクトリ（例：
`.claude/skills/sais-scan/`）にコピーして「セキュリティスキャンして」と
頼むと、エージェントが `sais` を実行し、JSON サマリを読んで所見を
レビュー観点として報告します。

### MCP サーバー

`mcp` エクストラを入れると（`pip install 'security-ai-scanner[mcp]'`）、
`sais mcp` でスキャナーを MCP（Model Context Protocol）サーバーとして
stdio 起動できます。Claude Code・VS Code・Cursor・Codex などの MCP
クライアントから、シェルを介さずスキャンを実行できます：

```bash
# Claude Code
claude mcp add sais -- sais mcp
```

```json
// VS Code / Cursor（mcp.json）
{ "servers": { "sais": { "command": "sais", "args": ["mcp"] } } }
```

ツールは `scan_repository(path, ...)`（実行サマリ＋`scan_id` を返す）、
`get_summary(scan_id)`、`get_findings(scan_id, min_severity)` の3つ。
スキャンは数分かかるため、実行中は MCP の progress 通知を送ります。

## 通知

`--notify-webhook URL`（または環境変数 `SAIS_NOTIFY_WEBHOOK`）で、スキャンの
完了時・失敗時に実行サマリを POST します。無人実行のスキャンが黙って失敗
することがなくなります：

```bash
# Discord チャンネルへ通知（件数とゲート判定のみ）
sais scan . --notify-webhook "$DISCORD_WEBHOOK_URL" --notify-format discord
```

`--notify-format` でペイロードを選べます：`generic`（サマリ JSON。CI・自作
受信先向け）／`discord`／`slack`。チャット形式は重要度別件数のみの1行
メッセージで、**所見の詳細（ファイル名・脆弱性内容）は送りません**。通知の
失敗は警告表示のみでスキャンの終了コードを変えず、URL は秘密情報として
一切表示しません。

## GitHub Action

このリポジトリは SARIF 出力を土台にした composite action としても使えます：

```yaml
- uses: elvezjp/security-ai-scanner@main
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: security-scan-results/findings.sarif
```

入力：`target`・`fail-on`・`language`・`output-dir`・`version`・`extra-args`。
出力：`sarif-file`・`summary-file`・`exit-code`。

この action は既定で PyPI の最新版スキャナーをインストールします。
CI の再現性が必要な場合は `version: "0.3.0"` のように固定してください。
action の参照タグを固定してもスキャナー本体は固定されません。

## 動作の仕組み

```
┌─────────────┐  プロンプト＋     ┌──────────────────┐
│ スキャナコア │  JSON Schema     │ エンジンアダプタ  │
│             │ ───────────────▶ │ (claude, ...)    │
│ 所見の検証   │                  └────────┬─────────┘
│ SARIF /     │                           │ 読み取り専用ツール
│ レポート生成 │                  ┌────────▼─────────┐
│             │ ◀─────────────── │ AI エージェントが │
└─────────────┘  構造化所見       │ リポジトリを読む  │
                                 └──────────────────┘
```

1. スキャナがセキュリティ監査プロンプトと所見の JSON Schema を組み立てる
2. エンジンが対象ディレクトリの上で AI エージェントを起動する（許可ツールは Read / Glob / Grep のみ）
3. エージェントがエントリポイントを把握し、データフローを追跡し、候補を検証した上で構造化出力として所見を返す
4. スキャナが所見を検証・整列し、SARIF / JSON / Markdown を書き出す

## ディレクトリ構成

```
security-ai-scanner/
├── security_ai_scanner/     # メインパッケージ
│   ├── cli.py               # コマンドラインインターフェース
│   ├── config.py            # スキャン設定
│   ├── findings.py          # 所見モデル・スキーマ・検証
│   ├── sarif.py             # SARIF 2.1.0 出力
│   ├── report.py            # Markdown レポート生成
│   ├── runner.py            # スキャンのオーケストレーション
│   ├── engine/              # エンジンアダプタ (claude, ...)
│   └── prompts/             # スキャン手法プロンプト
├── tests/                   # テストスイート
├── spec.md                  # 仕様書
├── docs/                    # ドキュメント
├── pyproject.toml           # プロジェクトメタデータ
├── LICENSE                  # MIT ライセンス
├── README.md / _ja.md       # README（英語 / 日本語）
├── CONTRIBUTING.md / _ja.md # コントリビューションガイド（英語 / 日本語）
├── SECURITY.md / _ja.md     # セキュリティポリシー（英語 / 日本語）
└── CHANGELOG.md / _ja.md    # 更新履歴（英語 / 日本語）
```

## セキュリティ

セキュリティ上の懸念については [SECURITY_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/SECURITY_ja.md) を参照してください。

**重要な注意点:**
- スキャンエージェントは読み取り専用ツールで動作し、対象の変更やコードの実行は行いません
- 解析のためにリポジトリの内容が設定された AI エンジンに送信されます。そのエンジンへの送信が許可されているコードのみをスキャンしてください。コードを自社インフラの外に出せない場合は、`--base-url` に自社ホストのエンドポイントを指定してください
- 所見には誤検出・見逃しが含まれ得ます。レポートは人によるレビューへの専門的な入力であり、保証ではありません
- 自身が所有するか、評価の許可を得ているコードのみをスキャンしてください

## コントリビューション

コントリビューションを歓迎します。詳細は [CONTRIBUTING_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CONTRIBUTING_ja.md) を参照してください。

- バグ報告は [GitHub Issues](https://github.com/elvezjp/security-ai-scanner/issues) へ
- 改善のプルリクエストを歓迎します
- 既存のコードスタイルに従ってください
- 新機能にはテストを追加してください

## ロードマップ

公開スキャナを CI・自社ホスト LLM で実用するための計画です（優先度順。約束ではなく、フィードバックで変わり得ます）。
対応 Issue には `priority:P0` / `P1` / `P2` と `roadmap` ラベルを付けています。

### P0 — 公開 CI・ローカルスキャンでまず使えること

- **パス include/exclude と `.saisignore`** — `node_modules` やビルド成果物などノイズを除外（[#3](https://github.com/elvezjp/security-ai-scanner/issues/3)）
- **プロジェクト設定ファイル**（`sais.toml` / `.sais.yaml`）— モデル・エンドポイント・fail-on・言語・スコープを固定（[#4](https://github.com/elvezjp/security-ai-scanner/issues/4)）
- **差分スキャン** — PR・コミット範囲に限定（[#5](https://github.com/elvezjp/security-ai-scanner/issues/5)）
- **ベースライン・抑止・安定した所見 ID** — 反復する誤検出で毎回 CI が落ちないようにする（[#6](https://github.com/elvezjp/security-ai-scanner/issues/6)）

### P1 — 汎用プロダクトとしての厚み

- **完了：第2エンジン** — OpenAI 互換アダプタにより、Claude に限定されないエンジン非依存コアを実証済み（[#7](https://github.com/elvezjp/security-ai-scanner/issues/7)、[#17](https://github.com/elvezjp/security-ai-scanner/pull/17)）
- **スキャンプロファイル** — 手法プロンプトの差し替え（既定 `security`＋少数の汎用プロファイル。組織固有チェックリストは公開コアにハードコードしない）（[#8](https://github.com/elvezjp/security-ai-scanner/issues/8)）
- **バッチスキャン** — 複数ルートの直列実行と `batch-summary.json`（当面は `sais scan` のループで各 `summary.json` を読む）（[#9](https://github.com/elvezjp/security-ai-scanner/issues/9)）
- **ローカル LLM 運用の強化** — コンテキスト枯渇時の明示エラー、単一セッション向け直列の案内（[#10](https://github.com/elvezjp/security-ai-scanner/issues/10)）

### P2 — 信頼と継続利用

- **既知脆弱フィクスチャのベンチ** — ホスト／ローカルの再現可能な recall 比較（[#11](https://github.com/elvezjp/security-ai-scanner/issues/11)）
- **トリアージ** — 既存所見の再評価・誤検出フィードバック（[#12](https://github.com/elvezjp/security-ai-scanner/issues/12)）
- **リリース成熟度** — サポートマトリクス、可能な範囲での SBOM、Action のピン留め案内（[#13](https://github.com/elvezjp/security-ai-scanner/issues/13)）

### 公開コアの非目標

- ベンダー／組織固有の「リポジトリ衛生」チェックリスト（docs の食い違い、内部 ADR ルールなど）。プライベートなラッパや、計画中の `--profile`（[#8](https://github.com/elvezjp/security-ai-scanner/issues/8)）で外から渡す
- 汎用コードレビューボット化。プロダクトの焦点は、根拠付きのセキュリティ所見のままにする

## 更新履歴

詳細は [CHANGELOG_ja.md](https://github.com/elvezjp/security-ai-scanner/blob/main/CHANGELOG_ja.md) を参照してください。

## 背景

本ツールは、日本語の開発文書・仕様書を対象とした開発支援AI
**IXV（イクシブ）** の開発過程で生まれた小さな実用品です。

IXVでは、システム開発における日本語の文書について、理解・構造化・活用
という課題に取り組んでおり、本リポジトリでは、その一部を切り出して
公開しています。

スキャン手法（エージェント型スキャン → 検証 → 構造化所見）は、
[OpenAI Codex Security](https://github.com/openai/codex-security) の設計に
インスパイアされた独立実装です。両プロジェクトの間でコードの共有はありません。

## ライセンス

MIT ライセンス - 詳細は [LICENSE](https://github.com/elvezjp/security-ai-scanner/blob/main/LICENSE) を参照してください。

## 連絡先

- **Email**: info@elvez.co.jp
- **Company**: 株式会社エルブズ（Elvez, Inc.）
