# 測試工具包設計文件

本目錄是「多代理 AI 輔助程式開發測試工具包」的設計文件組合；原型程式在 repo 根目錄的 `toolkit/`，受測樣本在 `samples/`。術語以 repo 根目錄的 [`GLOSSARY.md`](../../GLOSSARY.md) 為準；拆分決定見 [`docs/adr/0001-split-architecture-document.md`](../adr/0001-split-architecture-document.md)，實作語言見 [`docs/adr/0002-implementation-languages-python-rust.md`](../adr/0002-implementation-languages-python-rust.md)。

## 四份文件

| 文件 | 用途 | 放什麼 | 不放什麼 |
| :--- | :--- | :--- | :--- |
| [`spec.md`](spec.md) 規格 | 規範性條文 | 有 `TK-` 編號的條文、定義（狀態、資料物件、欄位表）、驗收群組、追溯表 | 研究證據、設計理由超過三句的說明 |
| [`design-notes.md`](design-notes.md) 設計說明 | 為什麼這樣設計 | 研究證據、設計取捨、模型候選與查證狀態、技術棧與里程碑、已知限制、參考資料 [R] | 規範性條文 |
| [`review-log.md`](review-log.md) 審查處置紀錄 | 審查與修訂歷史 | 審查輸入 [S]、審查意見與裁定、修訂紀錄、取消的宣稱、舊版章節對照、尚待查證的事實 | — |
| [`v0.1-scope.md`](v0.1-scope.md) 《v0.1 最小範圍》 | 原型 v0.1 做什麼 | 依規格條文 v0.1 欄位整理的一頁清單 | 條文內容（只引用編號） |

`tools/build.py` 依 `spec.md` 的條文區塊與 `tools/groups.json` 產生驗收群組表、附錄 A 與 `v0.1-scope.md`（見下方檢查清單第 3、4 步）。

v1.3.6 以前的單一文件 `docs/research/vibe-coding-multiagent-testing-toolkit-architecture-v1.3.md` 已凍結，不再更新；舊審查意見引用的章節號以該檔為準。

## 每輪修訂的檢查清單

1. 四份文件的檔頭版本號與修訂日期一起更新，規格第 0.4 節的版本句也一起改。
2. 新條文接續該領域的最後一個編號；在 `review-log.md` 第 4 章加一列修訂紀錄。
3. 改完條文後執行 `python -I docs/toolkit/tools/build.py`，自動產生規格的驗收群組表（第 14 章）、附錄 A 追溯表與 `v0.1-scope.md`；不要手動編輯這三處。工具同時執行下方「自動檢查」的全部檢查。
4. 新條文的驗收群組預設依領域決定；要改歸其他群組，或新增群組、新增領域，編輯 `tools/groups.json` 後再執行第 3 步。
5. 新參考資料接續 [R] 編號，寫進 `design-notes.md` 第 7 章。
6. 依 repo 根目錄的 [`CODING_STANDARDS.md`](../../CODING_STANDARDS.md) 審查本輪 diff。
7. `python -I docs/toolkit/tools/build.py --check` 結束碼為 0，且 `CODING_STANDARDS.md` 每條規則都有結論，才提交。

## 版本規則

- 四份文件共用一個版本號，寫在每份文件的檔頭。
- 改動 `docs/toolkit/`（含本檔與 `tools/`）、`GLOSSARY.md`、`docs/adr/`、`CODING_STANDARDS.md` 或代理指示檔（`AGENTS.md`、`docs/agents/`）時，四份文件一起升版；沒改內容的文件只改檔頭版本號與修訂日期。`toolkit/` 與 `samples/` 的程式改動不升版。
- 結構性變更（拆分、重新分章）升第二位數；一般修訂升第三位數。
- 修訂紀錄只記在 `review-log.md` 第 4 章，寫明改了哪幾份。

## 條文規則

- **編號**：`TK-<領域>-<三位數字>`；一經發出不重用。刪除時標「已廢止」並保留；拆分時用新編號並記錄來源編號；編號與章節號無關。
- **用語**：須／不得／宜／可，定義見 `spec.md` 第 0.1 節。「須」「不得」必有驗收方式；「宜」有編號但不列入 v0.1 必做。
- **粒度**：一條條文對應一個可獨立驗收的要求；判斷標準是能不能寫出一個獨立的驗收測試。
- **格式**：

  ```markdown
  #### TK-SBX-001 不可信程式不得掛載宿主機控制通訊端
  - **等級**：不得
  - **條文**：……
  - **驗收**：……
  - **v0.1**：必做／可延後／不適用
  - **理由**：設計說明 §3.N
  - **來源**：v1.3.6 §x.y（改寫者註明「改寫」）；v1.4.0 以後新增的條文寫「v1.4.x 新增」
  ```

- 條文後可附「說明（非規範性）」引用區塊，只解釋，不新增要求。
- 定義類內容不給編號，用「定義：〇〇」小節，條文以〈定義：〇〇〉引用。
- 參考資料只在 `design-notes.md` 第 7 章維護一份，保留 [R] 編號，接續編號不重排；規格引用時沿用同一編號。

## 自動檢查

`python -I docs/toolkit/tools/build.py --check` 是這組文件的檢查指令，出錯時以結束碼 2 停止，產生結果過期時以結束碼 1 停止；有任何錯誤時不寫入任何檔案；錯誤的回報方式見 `tools/build.py` 開頭說明。它檢查：

- 條文區塊：欄位齊全且不空白、等級與 v0.1 值合法、「須」「不得」條文的驗收不是「—」、編號不重複也不跳號。
- 引用：規格與其他文件（設計說明、審查處置紀錄、本檔、`GLOSSARY.md`、ADR、研究筆記）中的 `TK-` 引用都指向存在的條文；[R] 參考資料在設計說明中只定義一次、編號從 1 連續，各文件引用的 [R] 都有定義。
- 版本：四份文件的檔頭版本一致，且與規格第 0.4 節的版本句相同。
- 換行：文件、工具、ADR、研究筆記與設定檔都是 LF。repo 根目錄的 `.gitattributes`（`* text=auto eol=lf`）讓 Git 在 checkout 時也保持 LF。
- 產生結果：驗收群組表、附錄 A 與 `v0.1-scope.md` 與條文一致。

兩道防線都執行這個指令：

- **提交前 hook**：`.githooks/pre-commit`。每個複本執行一次 `git config core.hooksPath .githooks` 後啟用。hook 檢查的是工作目錄，不是暫存區：只暫存部分修改時，檢查通過不代表提交的內容通過。
- **CI**：`.github/workflows/docs-check.yml`，在每次 push 與 PR 執行，並先跑工具本身的測試。直接推 `main` 時 CI 是事後警報；事前攔截靠 hook。

工具本身的測試在 `tools/test_build.py`，用 `python -I -m unittest discover -s docs/toolkit/tools` 執行；修改 `build.py` 時依 `CODING_STANDARDS.md` 第 14 條補測試。
