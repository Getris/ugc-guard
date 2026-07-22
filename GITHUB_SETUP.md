# GitHub setup for Getris/ugc-guard

## Replace the existing local project

Copy the contents of this folder over the existing repository working tree without deleting its hidden `.git` directory.

From the repository directory:

```powershell
git switch trigger-ci
git add .
git commit -m "Release UGC Guard 0.2.0 security hardening"
git push
```

The existing pull request from `trigger-ci` to `main` will update automatically.

## Repository settings

Recommended ruleset for `main`:

- require pull requests;
- block deletions and force pushes;
- require CI and CodeQL after they have completed successfully at least once;
- keep required approvals at `0` while the project has one maintainer;
- require conversation resolution;
- allow squash merge.

## npm publication

The package metadata uses `@getris/ugc-guard`. Confirm that the npm account owns the `@getris` scope before publishing. If it does not, change the package name and all installation/import examples before the first npm release.

Do not publish until CI is green and `npm pack --dry-run` shows only the intended package files.
