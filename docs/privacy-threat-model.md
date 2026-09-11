# Privacy Threat Model

## Status and purpose

This document defines the privacy and confidentiality boundary for any current or future LLM-assisted feature in `powerbi-doc-agent`.

The project is local-first. PBIP, PBIR, TMDL, DAX, Power Query M, filters, and generated canonical artifacts may contain information that is more sensitive than their file format suggests. A file that appears to contain only "metadata" can still disclose personal data, credentials, internal infrastructure, business rules, customer names, source-system topology, or literal values copied from production data.

This document is normative for the LLM boundary. It does not implement any control yet.

## Central rule

> **No raw data may reach an LLM.**

There is no opt-in that weakens this rule.

"Raw data" includes more than table rows. For the purpose of this project, raw data includes any unreviewed or unsanitized source content whose disclosure could reveal a person, a secret, a confidential business fact, an internal system, or a production value.

Therefore, an LLM must never receive, verbatim or substantially verbatim:

- report data rows or samples;
- literal filter or slicer values;
- raw PBIR JSON fragments;
- raw TMDL fragments;
- complete DAX expressions;
- complete Power Query M expressions;
- SQL text embedded in M or native queries;
- connection strings;
- credentials, tokens, API keys, cookies, authorization headers, SAS signatures, or passwords;
- local or network file paths;
- internal hostnames, server names, database names, workspace identifiers, tenant identifiers, gateway identifiers, or private endpoints unless they have first been replaced by non-reversible local placeholders;
- free-text descriptions, comments, labels, titles, annotations, or names that have not passed sanitization;
- any value whose sensitivity is uncertain.

The safe direction of travel is:

`raw local source -> deterministic local extraction -> privacy classification -> sanitization/minimization -> LLM-safe representation -> LLM`

The reverse shortcut, `raw source -> prompt`, is prohibited.

## Trust boundaries

### Trusted local zone

The following may be processed locally because extraction and auditing require access to the original project:

- PBIP project files;
- PBIR report definitions;
- TMDL semantic-model definitions;
- DAX expressions;
- Power Query M expressions;
- filter definitions and states;
- local canonical `model.json` artifacts;
- source hashes and provenance records.

Local processing does not make the content non-sensitive. It only means the content has not crossed the external-model boundary.

### Sanitization boundary

Anything intended for an LLM must pass through a dedicated privacy boundary before serialization into a prompt or provider request.

The boundary must be allowlist-based, not denylist-based. A field is not sent merely because no detector classified it as sensitive. A field is sent only if the system knows why that field is required and knows what sanitized representation is permitted.

When classification is ambiguous, the required behavior is **fail closed**: omit the field from the LLM payload.

### External-model zone

An LLM provider is outside the trusted local zone regardless of provider, deployment model, retention policy, enterprise contract, or user account type. Provider assurances may reduce risk but never change the rule that raw data is excluded before transmission.

## Information classes

### 1. Personally identifiable information (PII)

Examples include:

- names;
- email addresses;
- phone numbers;
- postal addresses;
- CPF, CNPJ when linked to a natural person, employee IDs, customer IDs, account numbers, device IDs, and similar identifiers;
- IP addresses and machine/user identifiers when they can be tied to an individual;
- precise locations;
- usernames or directory identities;
- free text that identifies or reasonably singles out a person.

PII can appear in schema names and metadata, not only in rows.

### 2. Sensitive personal data

Examples include information about:

- health or medical status;
- racial or ethnic origin;
- religion;
- political opinions or affiliation;
- trade-union affiliation;
- genetic or biometric characteristics;
- sex life or sexual orientation;
- other highly sensitive personal circumstances.

A model name such as `Patients_HIV`, a measure such as `ReligiousAffiliationCount`, or a filter fixed to a named individual can reveal sensitive information even with zero data rows present.

### 3. Secrets and authentication material

Examples include:

- passwords;
- bearer tokens;
- API keys;
- OAuth tokens or refresh tokens;
- authorization headers;
- private keys or certificates;
- database credentials;
- secrets embedded in URLs or query strings;
- signed storage URLs;
- gateway or service-account credentials;
- credentials placed accidentally in comments, parameters, M source expressions, or native SQL.

Secrets are never LLM-safe, even if redacted elsewhere in the same file.

### 4. Confidential metadata

Examples include:

- internal hostnames and domains;
- database and schema names;
- data-lake container/bucket names;
- network shares and UNC paths;
- local usernames embedded in file paths;
- tenant, workspace, capacity, gateway, dataset, report, and environment identifiers;
- client, supplier, employee, product, plant, project, or acquisition codenames;
- report/page/measure/table names that disclose business strategy or organizational structure;
- RLS role names and access logic;
- unpublished KPIs and business formulas;
- refresh topology and source-system architecture;
- source code comments that reveal operational details.

Confidential metadata is not automatically personal data, but it can still create material security or business risk if disclosed.

### 5. Raw business values

Examples include:

- sales amounts;
- prices and margins;
- dates tied to events;
- customer/vendor names;
- order numbers;
- account balances;
- quantities;
- free-text notes;
- selected slicer values;
- literal values embedded in expressions;
- examples copied into comments or descriptions.

These values are raw data for the purposes of the LLM boundary even when they appear in a metadata file.

## Exposure map by Power BI surface

| Surface | Where sensitive content may appear | Main risk | LLM treatment |
|---|---|---|---|
| PBIR | page names; visual titles/subtitles; text boxes; alt text; visual configuration; bookmarks; filters; slicer state; field references; custom-visual settings; report-level properties; query state | PII in labels, literal filter values, confidential report structure, prompt injection in free text | Never send raw PBIR. Extract only required structural facts, then sanitize names and remove all literals/free text unless explicitly classified safe |
| TMDL | model/table/column/measure names; descriptions; annotations; relationships; roles; partitions; expressions; cultures/translations; source metadata | sensitive schema names, source topology, RLS logic, embedded DAX/M, annotations containing secrets | Never send raw TMDL. Use a minimized structural representation with sensitive text removed or replaced by local placeholders |
| DAX | string literals; comments; hard-coded IDs; URLs; emails; customer names; dates; security logic; table/column names; dynamic format strings | PII or business values embedded in literals, disclosure of proprietary logic, prompt injection through comments/text | Do not send complete expressions. Derive local features such as dependency edges, function classes, complexity counts, or sanitized pseudocode that contains no original literals |
| Power Query M | source URLs; server/database names; file paths; query parameters; headers; native SQL; credentials accidentally hard-coded; comments; literal sample values; API endpoints | direct secret leakage, internal network disclosure, production identifiers and values | Do not send M source. Derive sanitized connector type, transformation categories, dependency graph, and other non-secret structural facts locally |
| Filters / slicers | report/page/visual filters; selected values; basic/advanced filter operands; bookmarks; RLS predicates; relative date state | production values, personal names/IDs, segmentation logic, sensitive categories | Send filter existence/type only when needed. Never send selected values, operands, raw predicates, or user-specific state |

## PBIR-specific threats

PBIR is JSON-based, but JSON is not inherently safe metadata.

Potential disclosure points include:

- `displayName`, title, subtitle, and page labels containing customer, employee, facility, or project names;
- text-box content containing narrative business information;
- accessibility text describing confidential metrics;
- visual-level, page-level, and report-level filter values;
- slicer state or bookmarks that capture production selections;
- visual queries that expose table/column names or semantic-model design;
- custom visual configuration that stores endpoints, identifiers, or arbitrary text;
- embedded URLs and navigation targets;
- IDs that can be correlated with Fabric/Power BI resources.

A future sanitizer must treat arbitrary PBIR strings as untrusted input. They may contain secrets or prompt-injection instructions and must not be copied into an LLM prompt by default.

## TMDL-specific threats

TMDL exposes rich semantic-model structure and may carry sensitive content in places that appear harmless.

Potential disclosure points include:

- table and column names that identify people, customers, diseases, contracts, or internal systems;
- descriptions and annotations containing operational notes;
- measures containing proprietary formulas;
- roles and row-level security expressions that reveal authorization strategy;
- partition definitions that reveal source systems;
- M expressions embedded in partitions;
- translations and cultures containing free text;
- source columns or lineage information that disclose internal architecture.

Names are not automatically safe. A table called `Employee_Terminations_2026` can itself be confidential even without any row values.

## DAX-specific threats

DAX must be considered source code plus potentially embedded data.

Sensitive material may appear as:

- hard-coded strings;
- hard-coded identifiers;
- `DATATABLE` contents;
- URL or path literals;
- comments;
- business thresholds and pricing logic;
- customer/vendor/product names;
- calculated security predicates;
- proprietary KPI definitions;
- values constructed with concatenation that detectors might miss if they inspect tokens independently.

For LLM-assisted explanation, the preferred representation is not a redacted copy of the full DAX expression. The safer default is a locally derived semantic summary: referenced entities, function families, dependency edges, iterator/aggregation presence, branching depth, and other structural features that are sufficient for documentation without reproducing the original expression.

If a future feature truly cannot operate without expression semantics, it must first define a separate approved sanitized intermediate representation. Sending the original expression is still prohibited.

## Power Query M-specific threats

M is a particularly high-risk surface because data-source configuration and transformation logic often coexist in the same expression.

Sensitive material may appear in:

- `Web.Contents` URLs and query parameters;
- `Sql.Database`, `PostgreSQL.Database`, `Odbc.DataSource`, or other connector arguments;
- local file and folder paths;
- SharePoint/OneDrive/ADLS/storage URLs;
- native SQL statements;
- HTTP headers;
- manually embedded bearer tokens or API keys;
- environment, tenant, workspace, database, schema, container, or bucket identifiers;
- usernames embedded in paths;
- literals used to replace, filter, join, or classify production data;
- comments and query names.

The LLM-safe form should prefer categories such as `SQL_DATABASE`, `HTTP_API`, `LOCAL_FILE`, `CLOUD_STORAGE`, `MERGE`, `FILTER`, or `TYPE_CAST` rather than the original endpoint, path, query, or value.

## Filter and slicer threats

Filters are metadata that often contain actual data values.

Examples include:

- `Customer = "Acme"`;
- `EmployeeId = 12345`;
- `Diagnosis = "..."`;
- date ranges exposing an incident window;
- geographic selections;
- account IDs;
- slicer state saved in bookmarks;
- RLS filters tied to user identity.

The existence and type of a filter can be useful documentation metadata. Its values generally are not.

A future LLM payload may state that a page has, for example, `2 categorical filters and 1 relative-date filter`, but must not include the selected categories, exact values, or raw filter expression.

## Additional threat scenarios

### Accidental exfiltration through "metadata"

The largest conceptual risk is treating all non-row content as safe. Schema names, descriptions, expressions, filters, paths, endpoints, and comments can contain production information. The system must classify content by disclosure risk, not by file extension or whether it is called metadata.

### Prompt injection from project content

Report text, comments, descriptions, measure names, annotations, and other source-controlled strings can contain instructions aimed at the model, intentionally or accidentally.

Source content must always be treated as data, never as trusted instructions. The strongest mitigation is to avoid transmitting raw source text. Sanitized identifiers that are permitted into a prompt must remain clearly separated from system/developer instructions.

### Secret leakage through diagnostics

Even if the final prompt is safe, debug logs, traces, exceptions, request dumps, temporary files, crash reports, or telemetry could reproduce raw expressions or paths.

Future implementation must ensure that observability follows the same minimization policy as provider payloads. Logging a forbidden value locally and then uploading the log is still disclosure.

### Cross-project contamination

Caches, embeddings, local indexes, conversation history, or persistent provider sessions can accidentally mix information between unrelated Power BI projects.

Any future LLM cache or derived representation must be scoped to the project and must contain only LLM-safe material.

### Re-identification from quasi-identifiers

Removing obvious names is insufficient when combinations of attributes can identify a person or organization. Exact dates, locations, rare role names, unique project identifiers, and low-frequency categories can be identifying in combination.

The sanitizer should prefer coarse structural categories over precise values.

### Hash leakage

A plain hash of a low-entropy sensitive value is not necessarily safe because an attacker may guess candidate values and compare hashes.

Hashes used for local deterministic fingerprints may remain local. They must not automatically be treated as safe tokens for LLM transmission.

### Model-output leakage

An LLM cannot reveal raw values that it never receives. This is another reason the privacy boundary must operate before the provider request rather than relying on prompt instructions such as "do not reveal secrets".

## LLM-safe payload contract

The future LLM layer should consume a dedicated sanitized representation rather than `model.json` directly.

Potentially permissible fields, after local classification and sanitization, include:

- counts of tables, columns, measures, pages, visuals, relationships, sources, and filters;
- data types when they do not encode sensitive names or values;
- relationship cardinality and direction;
- graph topology expressed with local opaque identifiers;
- connector categories such as `SQL_DATABASE` or `HTTP_API`, without endpoints;
- transformation categories such as `FILTER`, `JOIN`, `GROUP`, `TYPE_CAST`, or `SORT`;
- DAX function families or locally derived complexity metrics;
- presence/absence of RLS, without role names, user identifiers, or predicates;
- page/visual types using generic local identifiers;
- warnings expressed as codes rather than copied source text;
- aggregate structural statistics that contain no source literals.

Fields that are prohibited by default include:

- source rows or samples;
- literal values;
- raw names when those names have not been classified safe;
- descriptions, comments, annotations, titles, and free text;
- DAX/M/SQL source;
- filter operands;
- connection information;
- paths and URLs;
- secrets;
- provider credentials;
- personal identifiers;
- internal resource identifiers.

## Local pseudonyms and placeholders

When an LLM needs to reason about relationships between entities, stable local placeholders are preferable to original names.

Examples:

- `TABLE_001` instead of the original table name;
- `MEASURE_014` instead of the original measure name;
- `SOURCE_02` instead of a hostname/database pair;
- `PAGE_03` and `VISUAL_07` instead of user-authored titles.

A placeholder mapping may exist locally for reconstruction of documentation after the LLM response, but the mapping itself must not be transmitted to the LLM.

Placeholders should be generated locally and scoped to the project. They should not encode the original value and should not be reversible by the provider.

## Data minimization rules

Before any future LLM request, the system should be able to answer all of the following:

1. Why is each field required for this request?
2. Can the task be completed using a category, count, boolean, or opaque identifier instead?
3. Does the field contain or derive from a literal production value?
4. Could the field reveal a person, organization, customer, employee, system, path, endpoint, credential, or business secret?
5. Is the field free text from the source project?
6. Is the field needed at all?

If the answer creates uncertainty, omit the field.

## Logging, caching, and temporary artifacts

Future LLM integration must apply the following principles:

- do not log provider request bodies containing source-derived text;
- do not log raw DAX, M, SQL, filter values, connection strings, or secrets as part of LLM diagnostics;
- keep raw canonical artifacts local;
- keep any LLM cache restricted to sanitized payloads and sanitized responses;
- do not include raw source fragments in exception messages intended for telemetry;
- separate local debugging artifacts from any automatically uploaded telemetry;
- make retention explicit and minimal;
- never use production Power BI content as a hidden test fixture.

## Relationship to the current design

The existing design states that extraction may preserve original DAX and M expressions locally for provenance and auditing. That remains compatible with this threat model: local preservation is different from external transmission.

The existing design also mentions a possible future user opt-in for data sampling. For LLM integration, this threat model supersedes that possibility:

> **Raw data sampling to an LLM is not an allowed mode, even with user opt-in.**

A future feature that needs statistical context must derive non-sensitive aggregates locally and send only an approved minimized representation.

## Security properties required before enabling any LLM provider

No provider integration should be considered production-ready until the project can demonstrate, with tests, that:

1. the provider interface cannot consume raw `model.json` directly;
2. DAX, M, SQL, PBIR fragments, and filter values are excluded from the provider payload;
3. secrets and connection metadata are removed before serialization;
4. arbitrary free text is excluded unless explicitly classified and transformed;
5. entity relationships can be represented using local opaque identifiers;
6. uncertain fields are dropped rather than passed through;
7. request logging cannot reproduce forbidden content;
8. test fixtures contain synthetic data only;
9. prompt-injection strings in source metadata are treated as inert input and cannot alter system instructions;
10. an automated test can inspect the exact serialized outbound payload and prove that forbidden classes are absent.

These are design requirements only. This document intentionally does not introduce code or tests yet.

## Non-goals for this document

This document does not:

- implement a sanitizer;
- choose an LLM provider;
- define provider-specific retention guarantees;
- implement secret detection;
- change extractors or the canonical schema;
- alter existing local provenance behavior;
- provide a legal determination for a specific organization or dataset.

Its purpose is to establish the privacy boundary and the constraints that future implementation must satisfy.

## Default decision rule

When deciding whether a Power BI-derived field may be sent to an LLM, use this order:

1. **Is it raw, literal, free-form, secret, personal, internal, or uncertain?** Do not send it.
2. **Can it be replaced locally by a category, count, boolean, structural edge, or opaque project-scoped identifier?** Use that representation.
3. **Is the transformed field necessary for the requested LLM task?** If not, omit it.
4. **Only then may the sanitized field cross the LLM boundary.**

The burden of proof is on transmission, not on exclusion.