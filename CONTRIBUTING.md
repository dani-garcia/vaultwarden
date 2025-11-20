## Secure Development Governance — Branching Strategy

The following defines our mandated Gitflow branching strategy for secure development governance. This file documents expectations for feature development, hotfixes, and releases.

```markdown
## Branching Strategy: Gitflow Workflow

We use the Gitflow model to manage our development lifecycle. All feature development must be done against the 'develop' branch.

**Feature Branches:** Branch from `develop`. Merge back to `develop` via Pull Request.
**Hotfixes:** Branch from `main`. Merge to `main`, then merge immediately to `develop`.

No direct pushes to 'main' or 'develop' are allowed.
```

Please follow these rules when contributing. If you need an exception (emergency hotfix with org approval), open an issue describing the reason and obtain an explicit approval before bypassing the rules.
