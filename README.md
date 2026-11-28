# 多代理 AI 輔助程式開發測試工具包

替 AI 輔助開發（vibe coding）產出的應用做安全測試的工具包。核心做法是：測試需求由應用負責人確認、不從程式碼現況推導；測試只在隔離的本機環境執行；判定依實際狀態，不只看回應碼。

## 目前的狀態

- **設計文件是草案。** 規格、設計說明與審查紀錄都標示為架構設計草案，不是已實作或已驗證的聲明。
- **原型只涵蓋 v0.1 的最小流程**：對 Next.js 加 Supabase 專案做已知的物件越權測試，環境是本機的 Supabase 堆疊（E1）。v0.1 分兩階段驗收：v0.1a 是不呼叫模型的流程（目前在做的部分），v0.1b 是單模型審查（尚未動工）。範圍見 [`docs/toolkit/v0.1-scope.md`](docs/toolkit/v0.1-scope.md)。
- **已實作的工作階段**：前置檢查、動態執行、判定與報告。靜態與架構分析、模型審查、威脅與測試規劃三個階段尚未實作，報告裡標為 `not_run`。
- **還沒有的部分**：《v0.1 最小範圍》的必做條文中，模型適配、機密遮罩、資料路由、預算、提示注入防護、建置沙盒與資源限制、中斷後續跑都還沒有程式；`ScanManifest` 的執行限制中，請求數、時間與並行數會在派送前實際限制執行，費用上限與網路允許清單還只檢查有沒有填（E1 堆疊一律阻擋對外連線，清單所列目的地不會開放）。進度見 [#1](https://github.com/chinchiang/MultiAgentZeta/issues/1) 的子議題。
- **已有的部分**：從 `ScanManifest` 到 JSON 報告與 Markdown 的一次執行；S2 預設政策範本；確認清單；測試授權紀錄；覆核紀錄（決定者取自平台帳號）；報告驗證；觀測者與行為者兩條取得通道的分離；E1 堆疊的隔離（專用內部網路阻擋對外連線與外部名稱解析、宿主機只經本機回送位址進入、啟動後檢查每個容器）；最低證據包與報告必備內容（逐項列出具備、缺件與不適用，報告寫出後封存）；中止與清理（操作者以 SIGINT／SIGTERM 中止、系統在時間用盡或重置失敗時中止，依序停止派送、登出測試身分、銷毀環境並查證無殘留，報告記下原因、各步驟時間與三項中止時間）。

## 目錄

| 路徑 | 內容 |
| :--- | :--- |
| `docs/toolkit/` | 設計文件：規格 `spec.md`、設計說明 `design-notes.md`、審查處置紀錄 `review-log.md`、《v0.1 最小範圍》。維護規則見 [`docs/toolkit/README.md`](docs/toolkit/README.md) |
| `docs/adr/` | 架構決策紀錄（文件拆分、實作語言 Python 與 Rust） |
| `docs/agents/` | 議題追蹤器、分流標籤與領域文件的使用約定 |
| `toolkit/` | 原型程式、結構檔案（`schemas/`）、政策範本、快速測試與環境測試（`tests/`） |
| `samples/` | 受測樣本：`object-authz` 的有漏洞版、修補版、合法行為版、寬鬆更新政策版，以及各自只讓拒絕案例一項驗證不成立的兩個版本（拒絕訊息洩漏內容、回應 403 但有副作用） |
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

環境測試會啟動真的 Supabase 堆疊，跑一輪約半小時。用專用腳本讓它脫離目前的工作階段執行；腳本自己使用 `.venv`，不必先啟用：

```sh
export MAZ_SUPABASE_BIN="$(toolkit/tools/fetch-supabase-cli.sh)"   # 取得並驗證固定版本的 Supabase CLI
toolkit/tools/run-env-tests.sh NAME                                # 啟動；記錄在 scratch/logs/NAME.log
toolkit/tools/run-env-tests.sh --status NAME                       # 查進度與失敗
```

## 執行一次掃描

需要 Docker 與支援矩陣固定的 Supabase CLI。輸入是一份 `ScanManifest`（JSON），格式見規格〈定義：必要輸入〉；它引用的確認清單與測試授權紀錄要放在受測專案以外的控制區。

```sh
export MAZ_SUPABASE_BIN="$(toolkit/tools/fetch-supabase-cli.sh)"
.venv/bin/python -I toolkit/tools/scan_run.py --manifest MANIFEST.json --out REPORT_DIR
```

`REPORT_DIR` 須在受測專案以外，而且裡面沒有先前的報告；執行後會有 `report.json` 與 `report.md`。結束碼 0 表示寫出了報告，不論執行是完整完成、部分完成或受阻，狀態請看輸出的狀態行；2 表示輸入被拒絕、什麼都沒有開始；3 表示工具本身失敗。目前還沒有產生 `ScanManifest`、確認清單與測試授權紀錄的指令，要自己準備這三份檔案；`toolkit/tests/test_scan.py` 的 `manifest()` 是一個完整的例子。

## 修改文件

改 `docs/toolkit/`、`GLOSSARY.md` 或 `docs/adr/` 前先讀 [`docs/toolkit/README.md`](docs/toolkit/README.md)。提交前執行：

```sh
python3 -I docs/toolkit/tools/build.py --check
git config core.hooksPath .githooks   # 每個複本一次，啟用提交前檢查
```

## 工作流程

議題與規格放在 GitHub Issues（`chinchiang/MultiAgentZeta`），票的格式與分流標籤見 [`docs/agents/issue-tracker.md`](docs/agents/issue-tracker.md) 與 [`docs/agents/triage-labels.md`](docs/agents/triage-labels.md)。給程式代理的指示在 [`AGENTS.md`](AGENTS.md)。
