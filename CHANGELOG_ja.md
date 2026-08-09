# 更新履歴

[English](./CHANGELOG.md) | [日本語](./CHANGELOG_ja.md)

このプロジェクトの重要な変更はすべてこのファイルに記録されます。

フォーマットは [Keep a Changelog](https://keepachangelog.com/ja/1.0.0/) に基づき、
[セマンティック バージョニング](https://semver.org/lang/ja/) に準拠しています。

## [0.2.0] - 2026-08-09

### 追加

- **エージェント向けサマリ出力**：すべてのスキャンで `summary.json`（重要度別件数・ゲート判定・終了コード・所要時間・出力パス）を書き出すようになりました。`scan --json` で同じオブジェクトを stdout に1行 JSON として出力できます（エージェント・スクリプト向け）
- `AGENTS.md`：コーディングエージェント（Claude Code・Codex・Cursor・VS Code エージェント等）向けの利用契約（実行コマンド・終了コード・出力スキーマ・所要時間の目安）
- README にロードマップを追加（MCP サーバー・webhook 通知・GitHub Action・バッチスキャン・差分スキャン・トリアージ）
- **MCP サーバー**：`sais mcp` でスキャナーを MCP（Model Context Protocol）サーバーとして stdio 起動できます（Claude Code・VS Code・Cursor・Codex 等の MCP クライアント向け）。ツールは `scan_repository`・`get_summary`・`get_findings` の3つ。オプションの `mcp` エクストラが必要（`pip install 'security-ai-scanner[mcp]'`）。スキャン出力は一時ディレクトリに書き出し、スキャン対象リポジトリ内には書き込みません
- **Webhook 通知**：`--notify-webhook`（または `SAIS_NOTIFY_WEBHOOK`）で完了・失敗時に実行サマリを POST。`--notify-format` で `generic`（JSON）／`discord`／`slack` を選択。チャット形式は重要度別件数のみで所見詳細は送りません。通知失敗はスキャンの終了コードに影響せず、webhook URL は表示しません
- **GitHub Action**：composite action（`action.yml`）を同梱。スキャナーのインストールとスキャン実行を行い、`sarif-file`／`summary-file`／`exit-code` を出力します（`codeql-action/upload-sarif` との連携用）
- **Claude Code スキル**：`skills/sais-scan/SKILL.md` を同梱。`sais` を実行して JSON サマリを読み、所見をレビュー観点として報告するスキルです
- **ローカルLLM対応**: `--base-url` で自社ホストの Anthropic 互換推論サーバーを指定してスキャンできます。リポジトリの内容が自社インフラの外に出ません
- ローカルエンドポイント用の `--auth-token`、構造化出力を制御する `--structured-output` / `--no-structured-output`
- `--base-url` 指定時は、エージェントが使うモデルスロット（opus / sonnet / haiku / サブエージェント）をすべて `--model` に固定します（ローカルサーバーは通常ひとつのモデルしか提供しないため）
- `--base-url` 指定時は、ホスト型 API の認証情報（`ANTHROPIC_API_KEY`・`CLAUDE_CODE_OAUTH_TOKEN`）をエージェント子プロセスの環境からクリアします（ローカルエンドポイントより優先されるのを防ぐため）

- **CI**: Linux / Windows / macOS × Python 3.11・3.14 のテストマトリクスと、スキャンプロンプトが wheel に同梱されることを検証するビルドジョブ
- **リリースワークフロー**: タグ push を起点とする PyPI 公開と、手動実行の TestPyPI 公開。いずれも Trusted Publisher (OIDC) 認証で API トークンを保存しません。PyPI ジョブは git タグと `pyproject.toml` の version が食い違う場合に公開を中止します
- GitHub Actions を可変タグではなくコミット SHA で固定し、更新は dependabot が PR で提案します

### 変更

- **Python 3.11 以上が必須になりました**（従来は 3.10）
- `--base-url` 指定時は構造化出力を既定でオフにし、フェンス付き JSON ブロックを要求して解析する方式に切り替えます
- 自社ホストのエンドポイント利用時は、エンジンがトークン数から算出するコスト概算を表示しません（課金が発生しないため）

### セキュリティ

本リポジトリ自身の自己スキャンで検出した3件の指摘への対応（[#14](https://github.com/elvezjp/security-ai-scanner/issues/14)）:

- **非構造化出力モードでのCIゲート回避** (SAIS-0001, CWE-345): 所見のパース対象をエージェントの最終応答のみに限定し、スキャン対象（信頼できない）リポジトリの内容を引用し得る途中経過テキストは使わなくなりました。スキーマ適合の JSON ブロックが複数見つかった場合は、どれかを黙って採用せずスキャンをエラーにします
- **認証トークンの露出** (SAIS-0002, CWE-214): `--base-url` 用の認証トークンを環境変数 `SAIS_AUTH_TOKEN` でも渡せるようにしました。コマンドライン引数はプロセス一覧やシェル履歴に露出する旨をヘルプと README に注記しています。`--auth-token` を明示指定した場合は空文字であっても環境変数より優先します
- **レポートへの Markdown 注入** (SAIS-0003, CWE-116): 該当箇所（evidence）を囲むコードフェンスの長さを内容に応じて動的に決め、埋め込まれたバッククォートでフェンスを早期に閉じられないようにしました。タイトルは1行に正規化し、説明・推奨対応・総評中のブロック開始記号（ATX見出し・コードフェンス・Setext下線／区切り線 `===`・`---`・`___`・`***`）はエスケープします

## [0.1.0] - 2026-07-29

### 追加

- 初回リリース
- リポジトリディレクトリをエージェント型セキュリティスキャンする `security-ai-scanner scan` コマンド（短縮エイリアス: `sais`）
- 読み取り専用ツールポリシー付きの Claude Agent SDK エンジン（許可は Read / Glob / Grep のみ。Bash・Write・Edit・ネットワークツールは禁止）
- JSON Schema 制約付き構造化出力による所見生成（タイトル・重要度・確度・ファイル/行・CWE・該当箇所・推奨対応）
- GitHub Code Scanning 互換の SARIF 2.1.0 出力（`findings.sarif`）
- JSON 出力（`findings.json`）と Markdown レポート（`report.md`）
- CI ゲート: `--fail-on {critical,high,medium,low,info,none}`。しきい値以上の所見があれば終了コード 1
- レポート言語の日英切り替え（`--language`）
- ユーザー指定のスキャンコンテキスト（`--context`）。信頼できない解析入力として扱われます
- 将来のバックエンド追加に備えたエンジンアダプタ層（`--engine`、既定は `claude`）
- Python ライブラリ API: `ScanConfig` / `run_scan`
- 所見検証・SARIF 出力・レポート生成・オーケストレーション・CLI を対象としたテストスイート（44 テスト）

### 補記

- スキャン手法は [OpenAI Codex Security](https://github.com/openai/codex-security) の設計にインスパイアされた独立実装です。両プロジェクトの間でコードの共有はありません。

## リンク

- [リポジトリ](https://github.com/elvezjp/security-ai-scanner)
- [Issueトラッカー](https://github.com/elvezjp/security-ai-scanner/issues)

## バージョン比較

| バージョン | 主な機能 |
|------------|----------|
| 0.2.0      | ローカルLLM対応（`--base-url`）、エージェント向けサマリ出力（`--json`）、MCPサーバー、webhook通知、GitHub Action、Claude Codeスキル、自己スキャンのセキュリティ修正、Python 3.11以上必須 |
| 0.1.0      | 初回リリース — エージェント型スキャン、SARIF/JSON/Markdown出力、CIゲート |
