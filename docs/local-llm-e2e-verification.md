# Local LLM E2E Verification — `openai` Engine

End-to-end verification record for the OpenAI-compatible engine
([PR #17](https://github.com/elvezjp/security-ai-scanner/pull/17),
[#16](https://github.com/elvezjp/security-ai-scanner/issues/16)):
fully local scans with no hosted API and no third-party agent harness
in the loop. Unit tests mock the HTTP transport, so this record is the
evidence that the engine works against real servers.

Date: 2026-08-23. Hardware: Mac Studio (Apple Silicon, 512 GB RAM).

## Fixture

A 4-file Flask demo app with four planted vulnerabilities:

| Planted | CWE | Location |
|---|---|---|
| OS command injection (`subprocess` + `shell=True` on request input) | CWE-78 | `app/server.py` `/ping` |
| SQL injection (string interpolation into `execute`) | CWE-89 | `app/db.py` `get_user` |
| Path traversal (`send_file` on unsanitized filename) | CWE-22 | `app/server.py` `/download` |
| Hardcoded production API key | CWE-798 | `app/config.py` |

## Run 1: llama.cpp server + muse-glimmer-30B

- Server: `llama-server` (llama.cpp) with `--jinja`, ctx 65536, one slot
- Model: muse-glimmer-30B (18 GB GGUF, k-quant dynamic)
- Command: `sais scan <fixture> --engine openai --base-url http://127.0.0.1:8892/v1 --model muse-glimmer-30b`

**Result: 4 / 4 planted vulnerabilities found, plus one real unplanted
finding (`DEBUG = True`, CWE-489, medium). Zero false positives. Every
file path and line number exact. All findings confidence `high`.**
83 s, 15,310 tokens, exit code 1 (CI gate, as expected).

llama.cpp is a deliberately hard target: it **ignores the request's
`model` field**, which is exactly why `--model` has no default (a
guessed default would be recorded as a false model name in the
outputs), and its tool-calling support (`--jinja`) is stricter than
most gateways. The fenced-JSON output contract survived it end to end.

### Missing-model UX (same server)

`sais scan <fixture> --engine openai --base-url http://127.0.0.1:8892/v1`
(no `--model`) exits 2 with the server's real model listing fetched
from `GET /v1/models`:

```
error: --model is required for --engine openai (or set the SAIS_MODEL
environment variable). ...
Models available at http://127.0.0.1:8892/v1:
  muse-glimmer-30b
```

### Budget stop (same server)

`--max-tokens 3000` stopped the scan after the first tool round:
`summary.json` recorded `"stopped": "budget_exceeded"` and
`"total_tokens": 4524`, stderr carried the incomplete-scan warning,
partial outputs were written. Note the model's prose summary claimed
the repository "contains only a README" rather than admitting the
cut-off — the machine-readable `stopped` marker, not the prose, is the
source of truth. CI must check `stopped` is null before trusting a
clean result (documented in README).

## Run 2: Ollama + qwen2.5-coder:7b

- Server: Ollama 0.32.x (`http://127.0.0.1:11434/v1`)
- Model: qwen2.5-coder:7b (4.7 GB)

**Result: the transport layer worked; the model did not.** The
missing-model error correctly listed the server's models via
`GET /v1/models`. But on every scan attempt (4/4 runs) the 7B model
produced an immediate "repository is clean" verdict in ~0.5–2 s,
~1,300 tokens, **without executing a single tool call**. A raw API
probe showed why: it emits its tool calls as plain-text JSON in
`content` (with the tool *description* in the name field), which the
server cannot parse into `tool_calls`.

This run exposed a dangerous failure mode — a clean verdict with zero
files inspected exited 0 and would have passed a CI gate. The engine
now guards against it: **a final answer produced with zero executed
tool calls is an engine error (exit 2)**, with a message pointing at
missing function-calling support. Verified live against the same
setup:

```
error: Engine reported an error: model produced a final answer without
inspecting any files (no tool calls executed). ...
exit=2
```

The same guard treats "token budget exhausted before any file was
inspected" as an error rather than a trustworthy partial result.

## Run 3: Ollama + qwen3.8:27b

- Server: Ollama 0.32.x (`http://127.0.0.1:11434/v1`)
- Model: qwen3.8:27b (18 GB)

**Result: 4 / 4 planted vulnerabilities found, plus the unplanted
`DEBUG = True` finding. Zero false positives.** 131 s, 10,759 tokens,
exit code 1 (CI gate, as expected). Line numbers were exact or within
source-vs-sink line choice (e.g. the command injection cited the line
that reads the request parameter; the 30B run cited the `subprocess`
sink one line below — both defensible).

Notably, its summary correctly observed that `DEBUG = True` is *not
yet wired into the running app* (nothing imports it), and rated it
low — a sharper contextual judgment than the 30B run's medium. It
also connected the path-traversal bug to the hardcoded key ("the key
is readable over the network"), a compound-risk observation neither
planted nor prompted.

This validates the Run 2 conclusion from the success side: same
server, same scanner, same fixture — the 7B model could not drive the
tool loop at all, while a 27B model produced hosted-quality results.
Transport was never the problem.

## Run 4: Ollama + ornith-1.5:35b

- Server: Ollama 0.32.x (`http://127.0.0.1:11434/v1`)
- Model: ornith-1.5:35b (22 GB)

**Result: 4 / 4 planted vulnerabilities found, plus the unplanted
`DEBUG = True` finding. Zero false positives. Every line number
exact.** 25 s, 6,887 tokens — the fastest quality run of the set —
exit code 1 (CI gate, as expected).

Severity calibration was more conservative than the other passing
models: command injection rated high (not critical) and path traversal
medium. This matches the README's standing observation that local
models are weakest at judging *how much a finding matters*; the gate
outcome was unaffected.

## Conclusions

- The `openai` engine works end to end against real OpenAI-compatible
  servers; llama.cpp (`--jinja`) with a capable ~30B model produced
  hosted-quality results on the fixture (4/4, exact lines, zero false
  positives)
- Model capability is the gating factor, not the transport: on the same
  Ollama server, a 7B coder model could not drive the tool loop at all
  while 27B/35B models went 4/4 — prefer roughly 27B-class or larger
  for real scans
- Among passing models, detection was uniform (4/4 + the same bonus
  finding, zero false positives on every run); what varies is severity
  calibration and speed (25 s–131 s on the same fixture)
- Failure modes discovered live (silent no-inspection verdict) are now
  structural errors, covered by unit tests

---
## 日本語要約

openai エンジンの実機 E2E 記録。脆弱性4件を植えた Flask フィクスチャを、
(1) llama.cpp server + muse-glimmer-30B(18GB・完全ローカル)で 4/4 検出
＋実在問題1件を追加検出、誤検出ゼロ、行番号まで正確。`--model` 未指定
エラーの候補列挙、`--max-tokens` の予算停止(`stopped` マーカー記録)も
実機で確認。(2) Ollama + qwen2.5-coder:7b は接続・モデル列挙は動作したが、モデルが
ツールを一度も呼ばず即「クリーン」と誤答(4/4 再現)。この危険な偽陰性を
受け、「ツール実行ゼロの最終回答はエンジンエラー(exit 2)」のガードを
実装し、同環境で動作確認済み。(3) Ollama + qwen3.8:27b(18GB)は 4/4 検出＋DEBUG 未配線の文脈まで
正しく判断し誤検出ゼロ(131秒)。(4) Ollama + ornith-1.5:35b(22GB)も
4/4・誤検出ゼロ・行番号全件正確で最速(25秒)。ただし深刻度較正は
保守的寄りに揺れる。結論: トランスポートは実証済み、律速は
モデル能力。同一サーバで 7B は全滅・27B は完走なので、実運用は概ね
27B 級以上を推奨。
