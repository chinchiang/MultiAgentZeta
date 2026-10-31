# 事實查核：review-log §6.2 尚待查證事項

- 查核日期：2026-10-31
- 範圍：`docs/toolkit/review-log.md` §6.2 所列的前三項（Nemotron 免費端點淘汰與 Gemini 2.5 可用性、觀測者專用唯讀角色、其他供應商的提示快取保存條件）。第四項（首批版本）不在本次範圍。
- 方法：只採用一手來源（官方文件、官方 API 實際回應、官方原始碼儲存庫）。網頁引文透過 WebFetch 擷取；NVIDIA API 回應、NVIDIA 試用條款 PDF 與 GitHub 原始碼則直接取得原文。社群論壇只用來找線索，不當作證據。

## 摘要

| 項目 | 結論 | 證據等級 | 建議寫入規格的文字 |
| :--- | :--- | :--- | :--- |
| 1a. `nvidia/llama-3.3-nemotron-super-49b-v1.5` 免費端點 | 已經不只是「標示為將淘汰」，而是已經停止服務：託管 API 回傳 HTTP 410，生命週期結束（end of life）時間為 2026-08-26T09:00:00Z。 | 已核對的一手紀錄（API 實際回應） | 「`nvidia/llama-3.3-nemotron-super-49b-v1.5` 的 NIM 託管端點已於 2026-08-26 生命週期結束，呼叫時回傳 HTTP 410，不得列為候選模型。」 |
| 1b. `nvidia/nemotron-3-super-120b-a12b` 淘汰時程 | 官方頁面沒有任何淘汰公告或日期；2026-10-31 仍列在 `/v1/models`。NVIDIA 試用條款保留隨時停止服務的權利。 | 部分確認（只能確認「沒有公告」，無法確認未來時程） | 「`nvidia/nemotron-3-super-120b-a12b` 截至 2026-10-31 無淘汰公告；試用服務依條款可隨時停止，每次執行前須以 `/v1/models` 確認。」 |
| 1c. NIM 託管 API 結構化輸出參數 | `nemotron-3-super-120b-a12b` 的託管 API 參考文件沒有列出 `response_format`、`guided_json`、`nvext` 等參數。 | 未能以一手來源確認 | 暫不寫入 |
| 2a. Gemini 2.5（Gemini API） | 未棄用，但只開放給過去曾實際使用的使用者；沒有公布關閉日期。 | 已核對的一手紀錄 | 「Gemini API 上的 `gemini-2.5-pro`／`gemini-2.5-flash` 未棄用、未公布關閉日期，但只開放給過去曾使用的帳號，新帳號不得假設可用。」 |
| 2b. Gemini 2.5（Vertex AI） | Vertex AI 列出的退役日期為 2026-10-20（已經過了）；文件沒有提到新帳號限制。 | 已核對的一手紀錄（日期）／未明載（新帳號限制） | 「Vertex AI 上的 `gemini-2.5-pro`／`gemini-2.5-flash` 退役日期為 2026-10-20，不得列為候選模型。」 |
| 3. Supabase 觀測者唯讀角色 | 可行：可以建立具 `LOGIN` 的自訂角色並授予資料表或欄位層級的 `SELECT`。`postgres` 角色本身具 `BYPASSRLS`，因此可以把 `BYPASSRLS` 授予新角色（Supabase 文件明載）。透過共用連線池連線時，使用者名稱格式為 `[ROLE].[PROJECT-REF]`。本機 CLI 使用同一個 `supabase/postgres` 映像檔，但本機連線池預設關閉。 | 已核對的一手紀錄（本機行為一致屬推論） | 「觀測者身分使用專用 Postgres 角色（`LOGIN`、僅對判定所需資料表或欄位授予 `SELECT`；需要跨列讀取時，以 `BYPASSRLS` 或指定 `TO <role>` 的 SELECT 原則達成），不得使用 `service_role` 或 secret key。」 |
| 4a. OpenAI 提示快取 | GPT-5.6 以後（含 GPT-6.1 Sol）：預設自動啟用；`prompt_cache_options.ttl` 可設 `"30m"`（預設）或 `"12h"`（僅 Responses API），兩者都是最短保存時間。快取以加密 KV 張量形式存放在 GPU 本機儲存，24 小時到期後不保留；不跨組織、不跨區域處理邊界共用；與 ZDR 相容。 | 已核對的一手紀錄 | 「OpenAI 提示快取：以加密 KV 張量存放於 GPU 本機、最長 24 小時、組織隔離、與 ZDR 相容；GPT-6.1 Sol 的 TTL 參數為 `prompt_cache_options.ttl`（`30m`／`12h`）。」 |
| 4b. Google Gemini 快取 | Gemini API：隱式快取（implicit caching）預設啟用，只存在記憶體、以專案隔離、TTL 24 小時，官方稱不違反 ZDR。顯式快取（explicit caching）依使用者設定的 `ttl` 保存，但 Gemini 4 Argon 起不支援顯式快取。Vertex AI：分記憶體與持久兩層，最長 24 小時，可用 `disableCache` 全部關閉；持久層不支援 CMEK。 | 已核對的一手紀錄（Gemini API 顯式快取的預設 TTL 未載明） | 「Gemini 隱式快取：僅存於記憶體、專案隔離、TTL 24 小時；`gemini-4-argon` 不支援顯式快取。在 Vertex AI 上要做到零資料保存，必須以 `disableCache` 關閉快取。」 |
| 4c. NVIDIA NIM 託管 API 快取 | 沒有任何文件說明託管 API 的提示或 KV 快取及其保存方式。試用條款只寫：工作階段結束後不保存內容，但可能為安全或防濫用目的記錄。 | 未能以一手來源確認（快取部分） | 「NIM 託管 API 未公開提示快取的保存條件，在補上文件前標示為『未知』。」 |

## 1. NVIDIA Nemotron 免費端點淘汰

### 文件明載／API 實際回應

- `nvidia/llama-3.3-nemotron-super-49b-v1.5` 已經停止服務。2026-10-31 未帶金鑰對 `POST https://integrate.api.nvidia.com/v1/chat/completions` 送出請求，得到 HTTP 410（Gone）。這個回應在驗證身分之前就回傳，而同一時間另一個仍在服務的模型回傳的是 401。【F1】
  > "The model 'nvidia/llama-3.3-nemotron-super-49b-v1.5' has reached its end of life on 2026-08-26T09:00:00Z and is no longer available."
- 同一時間 `GET https://integrate.api.nvidia.com/v1/models` 共回傳 85 個模型，其中含 `nvidia/nemotron-3-super-120b-a12b`（另有 `nvidia/nemotron-3.5-super-vl-120b-a12b`），不含 `llama-3.3-nemotron-super-49b-v1.5`。這與已知資訊一致。【F2】
- 兩個模型的 build.nvidia.com 頁面與 NIM API 參考頁面都沒有任何淘汰或生命週期結束（end-of-life）公告。49b-v1.5 的頁面只寫可透過 preview API 試用。【F3】【F4】【F5】
  > "You can try this model out through the preview API, using this link"
- NVIDIA 試用條款（API Trial Terms of Service）第 8 條保留隨時停止服務的權利：【F6】
  > "NVIDIA may at any time change, discontinue, or deprecate any part, or all, of the API Service, or change or remove features or functionality of the API Service."
- NIM API 文件的常見問題寫明，免費端點是開發者計畫（Developer Program）會員的原型開發用途：【F7】
  > "Members of the NVIDIA Developer Program have free access to NIM API endpoints for prototyping"
- 結構化輸出：`nemotron-3-super-120b-a12b` 託管 API 參考頁的請求主體（request body）參數只有 `model`、`messages`、`max_tokens`、`temperature`、`top_p`、`seed`、`stop`、`stream`、`reasoning_effort`、`reasoning_budget`。頁面中找不到 `response_format`、`json_schema`、`guided_json`、`nvext`。【F5】

### 推論與未確認

- 找不到任何官方的「淘汰公告頁」或附日期的事前公告。早期草稿所說的「已標示將淘汰（marked for retirement）」，無法以一手文件重現；能確認的只有事後的 410 回應。NVIDIA 開發者論壇的使用者貼文提到，build.nvidia.com 的 deploy 頁面曾顯示「This API will be deprecated on …」橫幅，同一天也有其他模型一起到期。但這屬於二手資料，而且頁面需要 JavaScript 才能呈現，本次無法擷取。
- `nemotron-3-super-120b-a12b` 的未來時程：未能以一手來源確認。
- 結構化輸出參數：託管 API 是否接受 vLLM 風格的 `guided_json` 或 OpenAI 風格的 `response_format`，未能以一手來源確認。自架 NIM 的 LLM 文件在本次擷取時無法取得內文。需要用有效金鑰實際測試，或等 NVIDIA 補上文件。

## 2. Gemini 2.5 對新帳號的可用性

### 文件明載

- Gemini API 模型頁（ai.google.dev）：【F8】
  > "we are limiting access to the 2.5 models to users who have actively used them in the past"
  > "These models are not deprecated and will continue to be served until further notice through the API."
  - 同一頁也寫：「For any new projects, use our latest models: 3.5 Flash-Lite or 3.8 Flash.」
- Gemini API 棄用頁（deprecations）：`gemini-2.5-pro` 與 `gemini-2.5-flash` 的發布日期都是 June 17, 2025，關閉日期一欄寫「No shutdown date announced」；`gemini-2.5-flash-lite` 也一樣。同一段使用限制說明在這一頁也重複出現。【F9】
- Vertex AI 模型版本頁（docs.cloud.google.com，Vertex AI 現在也稱為 Gemini Enterprise Agent Platform）：`gemini-2.5-pro` 與 `gemini-2.5-flash` 的 Retirement date 都是 October 20, 2026。替代模型分別為 `gemini-3.8-flash` 或 `gemini-3.5-flash`，以及 `gemini-3.8-flash` 或 `gemini-3.5-flash-lite`。【F10】
  > "While retirement timelines may be extended, they won't be moved to an earlier date than what is listed."
- Vertex AI 的 `gemini-2.5-pro` 模型頁：【F11】
  > "This model is being retired on October 20th, 2026."
  - 這一頁也說明，退役日期只適用於 Agent Platform；同一模型在該日期之後仍可能透過 Gemini API 存取。

### 推論與未確認

- Vertex AI 的文件沒有提到「只開放給過去曾使用的帳號」這項限制，所以這項限制只在 Gemini API 上明載。不過 Vertex AI 的退役日期已經過了，對新帳號來說這個差別沒有實際意義。
- 模型版本頁的最後更新日是 2026-10-30，晚於退役日期，但頁面仍列出這兩個模型。退役是否已實際執行（例如呼叫時回傳錯誤），本次沒有用 GCP 帳號實測，未能確認。

## 3. Supabase 觀測者唯讀角色

### 文件明載

**(a) 建立具 LOGIN 的自訂角色並授予 SELECT**

- Supabase 文件提供範例 `create role "role_name" with login password 'extremely_secure_password';`，並建議每個需要存取的服務各用一個角色，不要共用 `postgres` 的帳密。【F12】
  > "Roles can be granted various permissions on database objects using the `GRANT` command."
- PostgreSQL 18 文件說明欄位層級權限的語法 `GRANT SELECT ( column_name [, ...] ) ON table_name TO role`：【F13】
  > "A user may perform `SELECT`, `INSERT`, etc. on a column if they hold that privilege for either the specific column or its whole table."
- Supabase 欄位層級安全（Column-Level Security）頁面只示範 UPDATE，但寫出一項注意事項：受欄位限制的角色不能用 `select *`。【F14】
  > "Restricted roles cannot use the wildcard operator (`*`) on the affected table."

**(b) BYPASSRLS 與看見所有資料列的方式**

- Supabase 資料列層級安全（Row-Level Security, RLS）文件：【F15】
  > "You can also create new Postgres Roles which can bypass Row Level Security using the "bypass RLS" privilege:"
  - 範例為 `alter role "role_name" with bypassrls;`，並警告：「Never share login credentials for any Postgres Role with this privilege.」
  - 同一頁也寫：「A secret key authorizes access through the `service_role` Postgres role, which has the `bypassrls` attribute.」
- PostgreSQL 18 文件 CREATE ROLE：【F16】
  > "Only superuser roles or roles with `BYPASSRLS` can specify `BYPASSRLS`."
- PostgreSQL 18 文件 Row Security Policies 說明 BYPASSRLS 的效果，以及原則可以只套用到特定角色：【F17】
  > "Superusers and roles with the `BYPASSRLS` attribute always bypass the row security system when accessing a table."
  > "Row security policies can be specific to commands, or to roles, or to both."
- Supabase 的 `postgres` 角色不是超級使用者（superuser）：【F18】
  > "Superuser access is not given as it allows destructive operations to be performed on the database."
- 但 `postgres` 角色本身具有 `BYPASSRLS`。依據是 Supabase 官方映像檔原始碼（commit `e2841e5`，2026-10-30）：【F19】
  > `ALTER ROLE postgres NOSUPERUSER CREATEDB CREATEROLE LOGIN REPLICATION BYPASSRLS;`
  - 官方回歸測試的預期輸出 `nix/tests/expected/roles.out` 顯示，`postgres` 的 `rolsuper = f`、`rolcreaterole = t`、`rolbypassrls = t`。【F20】

**(c) 連線方式**

- 直接連線格式為 `postgresql://postgres:[YOUR-PASSWORD]@db.[PROJECT-REF].supabase.co:5432/postgres`。共用連線池（shared pooler）的 session 模式用 5432 埠，transaction 模式用 6543 埠。【F21】
  > "If you connect as a custom role through the shared pooler, the username is `[ROLE].[PROJECT-REF]`."
  - 同一頁也寫：直接連線預設走 IPv6，加購 IPv4 附加元件後才能用 IPv4；共用連線池在所有方案都只支援 IPv4。

**(d) 本機 Supabase CLI**

- CLI 的 `config.toml` 範本中，`[db]` 的 `port = 54322`、`major_version = 17`；`[db.pooler]` 的 `enabled = false`（本機連線池埠為 54329）。【F22】
- CLI 使用的映像檔是 `FROM supabase/postgres:17.11.0.011 AS pg`，與 F19、F20 來自同一個官方儲存庫。【F23】

### 推論

- 依 F16 加上 F19／F20：Supabase 的 `postgres` 使用者可以執行 `CREATE ROLE observer LOGIN BYPASSRLS ...`，F15 也直接證實這件事。因此「觀測者角色＝`BYPASSRLS` 加上最小 `SELECT` 授權」可行，而且不需要 `service_role` 或 `sb_secret_` 金鑰。
- 另一種做法：不用 `BYPASSRLS`，改為對受 RLS 保護的資料表建立 `CREATE POLICY ... FOR SELECT TO observer USING (true)`。這種做法的範圍限定在個別資料表，比 `BYPASSRLS` 更精細；依據是 F17 的一般 PostgreSQL 機制。
- 由於 `BYPASSRLS` 會略過所有資料表的 RLS，實際能讀到哪些資料就完全取決於 GRANT。不要把 schema 層級的預設權限授予這個角色。這一點屬於設計建議，不是文件明載。
- 本機 CLI 與雲端使用同一套角色定義，所以建立角色的行為應該一致。但本機預設沒有連線池，觀測者應直接連到 54322 埠；`[ROLE].[PROJECT-REF]` 這種使用者名稱格式只適用於雲端的共用連線池。本機連線池啟用後是否接受同樣格式，文件沒有寫，未確認。
- 雲端 Supabase 是否另有平台層（例如 supautils 擴充）限制把 `BYPASSRLS` 授予自訂角色：F15 明確寫可以，沒有看到相反的限制。本次沒有實際在雲端專案上測試。

## 4. 其他供應商的提示快取保存條件

（Anthropic 已查證，本次不重做。）

### 4a. OpenAI

**文件明載**【F24】

- 預設啟用：「Prompt caching is enabled by default for supported OpenAI models.」GPT-5.6 以後的模型，可快取的提示至少要 1,024 tokens。
- GPT-5.6 以後（含 `gpt-6.1-sol`）用 `prompt_cache_options.ttl` 設定最短保存時間，可選 `"30m"`（預設）或 `"12h"`：
  > "In the Responses API, you can choose a 12-hour minimum lifetime at a write rate of 2.5× ordinary input."
- 頁面點名 GPT-6.1 Sol 的快取讀取費率較低：「…0.05× on GPT-6.1 Sol… regardless of the selected lifetime.」
- 較早的模型改用 `prompt_cache_retention`，可選 `in_memory`（大約閒置 5 到 10 分鐘，最長 1 小時）或 `24h`。
- `prompt_cache_key` 只影響請求如何分配到機器：「Keys influence routing; they do not pin requests to a machine or guarantee a cache hit.」
- 存放位置：「Prompt caching may store encrypted key/value tensors in GPU-local storage as application state.」
- 隔離範圍：
  > "Caches are not shared across organizations and cannot be reused across regional processing boundaries."
- 與零資料保存（Zero Data Retention, ZDR）的關係：「All prompt caching features are compatible with Zero Data Retention (ZDR).」頁面也寫，沒有 ZDR 的組織（舊模型）預設用 `24h`，有 ZDR 的組織預設用 `in_memory`。

**資料控管頁（your data）**【F25】

> "This data is stored on the local GPU machines and is not retained after the 24-hour expiration."

- 同一頁也寫：GPT-5.6 以後，`prompt_cache_options.ttl` 控制的是最短保存時間，不是應用程式狀態的最長保存期限。

**推論**

- 對 `gpt-6.1-sol` 來說，實際的保存上限是 24 小時（應用程式狀態），TTL 參數只決定最短保存時間。

### 4b. Google Gemini

**文件明載（Gemini API）**

- 「Implicit caching is enabled by default for all Gemini 2.5 and newer models.」Gemini 4 Argon 的最低門檻是 4,096 tokens。【F26】
- 顯式快取：「…not supported in the Interactions API」，而且「or for Gemini 4 Argon and onward」也不支援。【F26】
- ZDR 頁：【F27】
  > "This data is strictly in RAM (not at-rest), isolated at the project level, and has a 24-hour TTL."
  - 這段講的是隱式快取，頁面稱不違反 ZDR。顯式快取則是：「the cached context itself is stored with a user-defined `ttl` or `expire_time`.」
  - 頁面也寫：需要保證零資料保存的工作負載應該改用 Vertex AI。
- `CachedContent.ttl` 的 API 參考只寫格式（以秒為單位、結尾加 `s`），沒有寫預設值或上下限。【F28】
- 付費服務條款：Google 會在「a limited period of time」內記錄提示與回應以偵測濫用；這些資料「may be stored transiently or cached in any country」。【F29】

**文件明載（Vertex AI）**

- 顯式快取的預設 TTL 是 60 分鐘，最短 1 分鐘：「There isn't a maximum cache duration.」隱式快取的保存期限最長 24 小時。持久層隱式快取只支援部分模型，Gemini 4 Argon 是其中之一。【F30】
- ZDR 頁：【F31】
  - 記憶體層：「It's stored only in memory, not at rest.」並寫明「deleted no later than 24 hours after it's written」。
  - 持久層：「stored at rest and encrypted with Google default encryption」；「Customer-managed encryption keys (CMEK) aren't supported for durable caching.」
  - 用 PATCH 把 `disableCache` 設為 true，可以同時停用兩層快取，「no cached data is retained」。

**推論與未確認**

- Gemini API 顯式快取的預設 TTL 與上限：本次擷取的頁面都沒有寫，未能確認。但 `gemini-4-argon` 本來就不支援顯式快取，所以對候選模型沒有影響。
- 在 Vertex AI 上使用 `gemini-4-argon` 時，如果沒有關閉快取，資料可能進入持久層並在靜態儲存（at rest）狀態保存最多 24 小時，且無法使用 CMEK。

### 4c. NVIDIA NIM 託管 API

**文件明載**

- 沒有任何文件說明託管 API 的提示快取或 KV 快取，以及其保存時間或隔離範圍。查過的範圍包括：NIM API 文件常見問題【F7】、`nemotron-3-super-120b-a12b` 參考頁【F5】、試用條款【F6】。
- 參考頁上的 `--kv-cache-dtype fp8`、`enable_block_reuse: false` 是自架部署的設定範例，不能當作託管 API 行為的說明。【F5】
- 試用條款 §2.3：【F6】
  > "NVIDIA will not store or use User Content or Generated Content at the end of each API Service session."
  - §2.4 另有例外：NVIDIA 為了安全或防範詐欺、濫用，可能記錄並保存內容。§3.3 寫：「Your use of the API Services will be logged for security, fraud or abuse monitoring」，並可能用使用者內容改善 NVIDIA 產品與模型。

**推論**

- 試用條款允許 NVIDIA 為了監控而記錄內容、為了改善產品而使用內容，因此 NIM 託管 API 不符合零資料保存。提示快取的保存條件應記為「未公開」。

## 來源

所有來源的查核日期都是 2026-10-31。

- F1 `POST https://integrate.api.nvidia.com/v1/chat/completions`（model=`nvidia/llama-3.3-nemotron-super-49b-v1.5`，HTTP 410 回應本文）
- F2 `GET https://integrate.api.nvidia.com/v1/models`
- F3 https://build.nvidia.com/nvidia/llama-3_3-nemotron-super-49b-v1_5
- F4 https://build.nvidia.com/nvidia/nemotron-3-super-120b-a12b
- F5 https://docs.api.nvidia.com/nim/reference/nvidia-nemotron-3-super-120b-a12b （以及 `-infer` 頁的請求主體參數）；另查 https://docs.api.nvidia.com/nim/reference/nvidia-llama-3_3-nemotron-super-49b-v1_5
- F6 NVIDIA API Trial Terms of Service，https://assets.ngc.nvidia.com/products/api-catalog/legal/NVIDIA%20API%20Trial%20Terms%20of%20Service.pdf （§2.3、§2.4、§3.3、§8）
- F7 https://docs.api.nvidia.com/nim/docs/product
- F8 https://ai.google.dev/gemini-api/docs/models
- F9 https://ai.google.dev/gemini-api/docs/deprecations
- F10 https://docs.cloud.google.com/vertex-ai/generative-ai/docs/learn/model-versions
- F11 https://docs.cloud.google.com/vertex-ai/generative-ai/docs/models/gemini/2-5-pro
- F12 https://supabase.com/docs/guides/database/postgres/roles
- F13 https://www.postgresql.org/docs/current/sql-grant.html （PostgreSQL 18.6）
- F14 https://supabase.com/docs/guides/database/postgres/column-level-security
- F15 https://supabase.com/docs/guides/database/postgres/row-level-security
- F16 https://www.postgresql.org/docs/current/sql-createrole.html （PostgreSQL 18.6）
- F17 https://www.postgresql.org/docs/current/ddl-rowsecurity.html （PostgreSQL 18.6）
- F18 https://supabase.com/docs/guides/database/postgres/roles-superuser
- F19 https://github.com/supabase/postgres/blob/e2841e5fc3afdbb49ac8d52e5e570f7c9da7565a/migrations/db/migrations/10000000000000_demote-postgres.sql
- F20 https://github.com/supabase/postgres/blob/e2841e5fc3afdbb49ac8d52e5e570f7c9da7565a/nix/tests/expected/roles.out
- F21 https://supabase.com/docs/guides/database/connecting-to-postgres
- F22 https://github.com/supabase/cli/blob/e365ad6b96a2ba4327b9220ecba5e4504e5fbecc/apps/cli/src/shared/init/project-init.templates.ts
- F23 https://github.com/supabase/cli/blob/e365ad6b96a2ba4327b9220ecba5e4504e5fbecc/apps/cli/src/shared/services/Dockerfile
- F24 https://developers.openai.com/api/docs/guides/prompt-caching （由 platform.openai.com/docs/guides/prompt-caching 301 轉址）
- F25 https://developers.openai.com/api/docs/guides/your-data
- F26 https://ai.google.dev/gemini-api/docs/caching
- F27 https://ai.google.dev/gemini-api/docs/zdr
- F28 https://ai.google.dev/api/caching
- F29 https://ai.google.dev/gemini-api/terms
- F30 https://docs.cloud.google.com/vertex-ai/generative-ai/docs/context-cache/context-cache-overview
- F31 https://docs.cloud.google.com/vertex-ai/generative-ai/docs/vertex-ai-zero-data-retention
