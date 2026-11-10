# templates

Template definitions (H2 spec §7.6): data files that describe the one-click workloads (with `allowed_routes` and the
`pull` parameter), compiled into a signed bundle at release.

**Empty for now.** The workspace scaffold (T2-00) only reserves the directory.

Filled by:

- T2-50: the two templates, the bundle compiler and signer (`scripts/templates-bundle`).
- T2-15: the server side that loads the bundle (outside this directory).
