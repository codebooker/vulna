# Reports and exports

Vulna renders reports from the durable snapshot of a **completed scan**. A report
does not re-query a changing live view halfway through generation, so its asset,
service, finding, remediation, and CVE sections describe one consistent result.

## Generate a report

1. Open **Management → Reports** and select **Generate report**.
2. Choose a completed scan.
3. Optionally filter the snapshot to one asset tag or materialized asset group.
   Site-scoped groups are offered only for a scan at the same site.
4. Select one or more output types and generate them.
5. Download completed artifacts from the report table.

Generation and download are sensitive actions and require recent step-up
authentication. `reports.create` and `reports.read` are evaluated independently,
and site-scoped users can access only reports for sites allowed by their grants.

## Output types

| Output | Intended use |
|---|---|
| Executive summary PDF | Plain-language posture, priorities, coverage, and trends for leadership. |
| Technical report PDF | Findings, affected assets, evidence, CVEs, and remediation guidance. |
| Pentest report PDF | Approved controlled-pentest scope, execution, evidence, and outcomes. |
| Full-spectrum assessment PDF | Combined executive, technical, inventory, remediation, and assessment view. |
| Findings CSV | Tabular finding data for analysis or ticket workflows. |
| Assets CSV | Asset inventory and context. |
| Services CSV | Discovered services and exposure. |
| CVE exposure CSV | CVE-to-asset exposure with enrichment. |
| JSON bundle | Versioned machine-readable snapshot for approved downstream processing. |

CSV exporters neutralize spreadsheet-formula prefixes. JSON schemas and CSV
columns are versioned so downstream consumers can detect change rather than
silently interpreting a new shape.

## From a scan

Users with report-generation permission can also start report generation from a
completed scan on **Operations → Scans**. The resulting artifacts appear in the
same Reports table. Failed or running scans cannot be selected.

## Automation

The API supports durable queued generation with an idempotency key, and report
templates can schedule permission-scoped inventory and analytics outputs. See
[Inventory intelligence](passive-inventory.md) and
[durable tasks](background-tasks.md) for those operator workflows.

## Storage, expiry, and backups

Report files are stored in the appliance's persistent report volume and metadata
is stored in PostgreSQL. Each artifact has an expiry; an expired report cannot be
downloaded even before the retention worker removes its file. Configure retention
to match your evidence-handling policy.

Reports can contain hostnames, addresses, evidence, vulnerability details, and
remediation history. Treat them as sensitive. Encrypted backup/restore preserves
report state and files when the report volume is included; portability exports do
not substitute for a full encrypted backup. See [backups](backups.md),
[privacy](privacy.md), and the [data map](data-map.md).
