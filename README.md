# 多代理 AI 輔助程式開發測試工具包

替 AI 輔助開發（vibe coding）產出的應用做安全測試的工具包。核心做法是：測試需求由應用負責人確認、不從程式碼現況推導；測試只在隔離的本機環境執行；判定依實際狀態，不只看回應碼。

## 目前的狀態

- **設計文件是草案。** 規格、設計說明與審查紀錄都標示為架構設計草案，不是已實作或已驗證的聲明。
- **原型只涵蓋 v0.1 的最小流程**：對 Next.js 加 Supabase 專案做已知的物件越權測試，環境是本機的 Supabase 堆疊（E1）。範圍見 [`docs/toolkit/v0.1-scope.md`](docs/toolkit/v0.1-scope.md)。
- **已實作的工作階段**：前置檢查、動態執行、判定與報告。靜態與架構分析、模型審查、威脅與測試規劃三個階段尚未實作，報告裡標為 `not_run`。
- **已有的部分**：從 `ScanManifest` 到 JSON 報告與 Markdown 的一次執行；S2 預設政策範本；確認清單；測試授權紀錄；覆核紀錄（決定者取自平台帳號）；報告驗證；觀測者與行為者兩條取得通道的分離。

## 目錄

| 路徑 | 內容 |
| :--- | :--- |
| `docs/toolkit/` | 設計文件：規格 `spec.md`、設計說明 `design-notes.md`、審查處置紀錄 `review-log.md`、《v0.1 最小範圍》。維護規則見 [`docs/toolkit/README.md`](docs/toolkit/README.md) |
| `docs/adr/` | 架構決策紀錄（文件拆分、實作語言 Python 與 Rust） |
| `docs/agents/` | 議題追蹤器、分流標籤與領域文件的使用約定 |
| `toolkit/` | 原型程式、結構檔案（`schemas/`）、政策範本、快速測試與環境測試（`tests/`） |
| `samples/` | 受測樣本：`object-authz` 的有漏洞版、修補版、合法行為版與寬鬆更新政策版 |
| `GLOSSARY.md` | 核心術語；文件與議題一律用這裡的說法 |
| `CODING_STANDARDS.md` | 程式與文件的審查標準 |

## 開始使用

需要 Python 3 與 Docker（只有環境測試需要 Docker）。

```sh
# 安裝相依套件（雜湊鎖定）
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r toolkit/requirements.lock

# 快速測試：不需要 Docker，環境測試會略過
.venv/bin/python -I -m unittest discover -s toolkit/tests -t .

# 只跑一個檔案
.venv/bin/python -I -m unittest discover -s toolkit/tests -t . -p test_scan.py
```

環境測試會啟動真的 Supabase 堆疊，跑一輪約半小時。用專用腳本讓它脫離目前的工作階段執行。腳本用 `PATH` 上的 `python3`，不會自己找 `.venv`，所以先啟用它：

```sh
. .venv/bin/activate
export MAZ_SUPABASE_BIN="$(toolkit/tools/fetch-supabase-cli.sh)"   # 取得並驗證固定版本的 Supabase CLI
toolkit/tools/run-env-tests.sh NAME                                # 啟動；記錄在 scratch/logs/NAME.log
toolkit/tools/run-env-tests.sh --status NAME                       # 查進度與失敗
```

## 修改文件

改 `docs/toolkit/`、`GLOSSARY.md` 或 `docs/adr/` 前先讀 [`docs/toolkit/README.md`](docs/toolkit/README.md)。提交前執行：

```sh
python3 -I docs/toolkit/tools/build.py --check
git config core.hooksPath .githooks   # 每個複本一次，啟用提交前檢查
```

## 工作流程

議題與規格放在 GitHub Issues（`chinchiang/MultiAgentZeta`），票的格式與分流標籤見 [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md) 與 [`docs/agents/triage-labels.md`](docs/agents/triage-labels.md)。給程式代理的指示在 [`AGENTS.md`](AGENTS.md)。
