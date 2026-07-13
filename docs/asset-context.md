# Asset context, groups, and ownership

Phase 40 adds organization-owned context to inventory without changing scan scope
or authorization. Context improves search, reporting, prioritization, and assignment;
it never grants access to an asset. Every API continues to apply the caller's Phase
39 permission and site scope.

## Structured context and tags

Assets can record a department, business function, environment, criticality, data
classification, internet-exposure flag, explicit owner, and bounded custom JSON.
New fields have neutral defaults so existing inventory does not acquire an inferred
classification or owner during upgrade.

Tags are normalized per organization using Unicode case-insensitive names. The
legacy `tags_json` field remains a compatibility projection. The migration converts
each legacy value to a normalized tag and assignment while retaining its original
value, position, and asset metadata; later tag edits do not overwrite scanner
metadata.

Inventory search and reports accept normalized tag and materialized group filters.
Multiple report filters use AND semantics and are resolved server-side before the
snapshot is generated. Report snapshots preserve the selected filters and the
asset context that was effective at generation time.

## Static and dynamic groups

Static membership is explicit. Dynamic membership is materialized from a validated
JSON abstract syntax tree and refreshed after discovery, context, or tag changes.
Preview returns each matching asset with a structured explanation. Disabling a
dynamic group removes its materialized membership; re-enabling evaluates the rule
again.

A leaf has `field`, `operator`, and `value`. Boolean nodes use exactly one of `all`,
`any`, or `not`. Rules are bounded by depth, node count, and list size. Supported
fields are:

- `canonical_name`, `asset_type`, `status`, `operating_system`, `manufacturer`;
- `department`, `business_function`, `environment`, `criticality`;
- `data_classification`, `internet_exposed`, `site_id`, and `tag`.

Supported operators are `eq`, `neq`, `contains`, `starts_with`, `in`, `not_in`,
`is_null`, and `is_not_null`. Unknown fields/operators are
rejected. Rules are interpreted by an allowlisted evaluator; they are never Python,
SQL, regular expressions, templates, or shell expressions.

Example:

```json
{
  "all": [
    {"field": "environment", "operator": "eq", "value": "production"},
    {"field": "tag", "operator": "eq", "value": "payment tier"}
  ]
}
```

## Effective ownership

Vulna resolves ownership deterministically in this order:

1. explicit finding assignment;
2. explicit asset owner;
3. owner of the highest-priority enabled matching group;
4. site owner;
5. department owner;
6. unassigned.

An enabled ownership group must have a unique priority among groups that could
overlap. Configuration rejects a potential tie, and runtime resolution also fails
closed if legacy or externally modified data contains one. Changes to assignments,
context, tags, groups, site owners, and department owners append a snapshot only
when the effective result changes. History retains the selected source and a
human-readable explanation.

## API and operations

The additive `/api/v1` interfaces include:

- `PATCH /assets/{id}/context`, `POST /assets/bulk`, and asset tag/ownership history;
- `/asset-tags` and `/asset-groups`, including preview, evaluation, and membership;
- `/department-owners`; and
- inventory/report query filters for tags, groups, context, and explicit owner.

`assets.read` permits the scoped read surfaces. `assets.manage` is required for
mutation, and organization-wide tag/department management requires an organization
grant. Every mutation is audited. SCIM identity-group mappings can now reference
validated asset-group ids, but such a mapping does not bypass asset authorization.

Phase 40 records are included in encrypted database backups. Non-secret structured
context, normalized tags/groups, membership explanations, and ownership history are
also included in portability schema v4. User credentials, tokens, evidence, and raw
scanner output remain excluded.
