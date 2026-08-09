# security-ai-scanner へのコントリビューション

[English](./CONTRIBUTING.md) | [日本語](./CONTRIBUTING_ja.md)

このドキュメントは、プロジェクトへのコントリビューションのガイドラインを説明します。

## コントリビューションの方法

### バグ報告

バグを見つけた場合は、以下の情報を添えて GitHub に Issue を作成してください。

- 明確で説明的なタイトル
- 再現手順
- 期待される動作
- 実際の動作
- スキャン対象の言語・フレームワーク（可能なら最小再現リポジトリ）
- security-ai-scanner と Python のバージョン
- 使用したエンジンとモデル（例: `claude`、既定モデル）
- オペレーティングシステム

非公開コードベースの実際の脆弱性の詳細を、公開 Issue に書かないでください。
security-ai-scanner 自体の脆弱性については [SECURITY_ja.md](./SECURITY_ja.md)
に従ってください。

### 機能リクエスト

機能リクエストを歓迎します。以下を添えて Issue を作成してください。

- 明確で説明的なタイトル
- 提案する機能の詳細な説明
- ユースケースとメリット
- 関連する例やモックアップ

### プルリクエスト

1. **リポジトリをフォーク**し、`main` からブランチを作成します（形式: ユーザー名/YYYYMMDD-説明）
   ```bash
   git checkout -b user/20260729-fix-feature
   ```

2. **既存コードベースのコーディングスタイルに従ってください**
   - 意味のある変数名・関数名を使う
   - 複雑なロジックにはコメントを付ける
   - PEP 8 スタイルガイドに従う

3. **変更に対するテストを書いてください**
   ```bash
   # テストの実行
   uv run pytest tests

   # カバレッジ付きで実行
   uv run pytest tests --cov=security_ai_scanner --cov-report=html
   ```

4. **必要に応じてドキュメントを更新してください**
   - ユーザー向けの変更は README.md / README_ja.md を更新
   - 仕様の変更は spec.md を更新

5. **明確なコミットメッセージでコミットしてください**

   形式: `<type>: <概要>`。`<type>` は `feat`・`fix`・`docs`・`test`・
   `refactor`・`ci`・`chore`・`deps`・`release` のいずれかを使います。
   関連する Issue や PR がある場合は本文に `#<番号>` で参照してください。

   ```
   # 良い例
   fix: handle empty findings list in markdown report
   feat: add --max-turns option to cap agent turns (#42)

   # 避けたい例
   fix bug
   updates
   ```

6. **フォークにプッシュ**し、プルリクエストを作成してください

7. **レビューをお待ちください** - メンテナーがレビューし、変更をお願いする場合があります

## 開発環境のセットアップ

### 前提条件

- Python 3.11 以上
- uv パッケージマネージャー

### インストール

```bash
# uv のインストール（未導入の場合）
# 詳細: https://docs.astral.sh/uv/getting-started/installation/
curl -LsSf https://astral.sh/uv/install.sh | sh

# フォークをクローン
git clone https://github.com/YOUR-USERNAME/security-ai-scanner.git
cd security-ai-scanner

# 依存関係のインストール（テスト依存を含む）
uv sync --extra test
```

### テストの実行

```bash
# 全テストの実行（AI エンジンやネットワークアクセスは不要）
uv run pytest tests

# 特定のテストファイルの実行
uv run pytest tests/test_findings.py

# カバレッジ付きで実行
uv run pytest tests --cov=security_ai_scanner --cov-report=html
```

ユニットテストはモックエンジンを使用し、実際の AI バックエンドを呼び出しません。
実エンジンの動作確認は、自身が所有する小さなリポジトリへのスキャンで行ってください。

```bash
uv run security-ai-scanner scan path/to/small-repo -v
```

実スキャンはエンジン（API）の利用量を消費する点に注意してください。

## CI とリリース

`main` への push とプルリクエストのたびに、テストマトリクス
（Linux / Windows / macOS × Python 3.11・3.14）と、スキャンプロンプトが
wheel に同梱されることを検証するビルドジョブが走ります。テストは
モックエンジンを使うため、CI に AI の認証情報は不要で、ネットワーク
アクセスも発生しません。

リリースはタグ起点です。

```bash
# 先に pyproject.toml の version を上げ、CHANGELOG を更新する
git tag v0.2.0
git push origin v0.2.0
```

公開ワークフローはテストを再実行し、タグと `pyproject.toml` の version
が食い違う場合は公開を中止します。PyPI へのアップロードは Trusted
Publisher (OIDC) 認証で行うため、API トークンはリポジトリに保存しません。
公開経路を事前に確認したい場合は、Actions タブから **Publish to
TestPyPI** を手動実行してください。

GitHub Actions は可変タグではなくコミット SHA で固定しています。
タグの指し先が変わって CI が別のコードを実行してしまう余地をなくすため
です。更新は dependabot が月次で PR を出すので、SHA を手で書き換えるので
はなく、その PR をレビューしてください。

## コーディングガイドライン

### Python スタイル

- PEP 8 スタイルガイドに従う
- 型ヒントを使う（`from __future__ import annotations` スタイル）
- 1 行の最大長: 100 文字（長い文字列は柔軟に）
- 意味のある変数名を使う
- 公開関数・クラスには docstring を付け、シグネチャの繰り返しではなく
  「何を・なぜ」を書く。名前だけで挙動が明確な小さな非公開ヘルパーには
  docstring を省略してよい

### アーキテクチャのルール

- スキャナコア（`config`・`findings`・`sarif`・`report`・`runner`）は
  エンジン非依存を保つこと。エンジン SDK をコアで import しない
- エンジン固有のコードは `security_ai_scanner/engine/` に置く。
  新しいバックエンドは `ScanEngine` を実装し `get_engine()` に登録する
- スキャン手法のテキストは `security_ai_scanner/prompts/` に置き、
  バックエンド中立に保つ
- スキャン対象のリポジトリ内容とユーザー指定コンテキストは、プロンプト内で
  常に「信頼できないデータ」として扱い、指示として扱わない

## 質問

バグでも機能リクエストでもない質問は info@elvez.co.jp までご連絡ください。
