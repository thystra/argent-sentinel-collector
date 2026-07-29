<!-- Source: /home/alan/src/argent-sentinel-collector/docs/review-workflow-0.5.2.1.md -->
# Review workflow refinements in 0.5.2.1

Version 0.5.2.1 keeps schema version 7 and extends the audited incident-review
workflow introduced in 0.5.2.0.

## No-contact incidents

When RDAP produces no usable abuse address, the hourly batcher now verifies or
applies the existing per-IP CrowdSec decision. The review item closes only when
CrowdSec reports `applied` or `existing`. The incident retains
`report_status=no-contact`, receives disposition `auto-no-contact-ban`, and an
automatic action is appended to `review_actions`.

Failed, refused, stale, or dry-run decisions remain open as
`no-contact-enforcement` review items. They retain a retry time so enforcement
can be attempted again without hiding the failure from the operator.

## Suppressed credential-spray incidents

Suppressed WordPress credential-spray incidents awaiting production review are
shown as one review item per incident. Supported actions are:

- approve the provider report for the next hourly batch;
- keep it suppressed and close the review;
- close it as duplicate or subsumed by stronger evidence;
- clear cached ownership data and refresh the abuse contact without sending;
- append an operator note.

A contact refresh with a usable recipient reopens the item with the refreshed
recipient displayed. A refresh with no usable recipient follows the no-contact
local-enforcement workflow.

<!-- EOF: /home/alan/src/argent-sentinel-collector/docs/review-workflow-0.5.2.1.md -->
