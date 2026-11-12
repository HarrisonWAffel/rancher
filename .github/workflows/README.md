# Description of GitHub Actions in this repository

## PR provisioning tests (`test-slash-command.yml`, `slash-provisioning-tests.yml`)

Organization members can run selected provisioning tests on an open pull request:

```text
/ptest rke2,Test_Provisioning_Example k3s,Test_Operation_Example
```

Each whitespace-separated entry creates one job. Specify `rke2` or `k3s` before
the comma; omitting the distribution (`Test_Example` or `,Test_Example`) defaults
to `rke2`. Supply 1 to 16 entries. Regexes are limited to 256 characters, cannot
contain whitespace, and must use the characters accepted by
`scripts/provisioning-tests`. 

The command is handled in two stages:

1. `test-slash-command.yml` runs on the comment in the trusted base repository
   context. It never checks out PR code. It validates the request, replies with
   the PR head commit and matrix (recorded in a hidden marker), and applies the
   `ptest` label.
2. Adding the label triggers `slash-provisioning-tests.yml` as a `pull_request`
   run, so fork PRs get the usual sandbox (read-only token, no secrets,
   PR-scoped cache) and results show up in the PR's checks. It reads the latest
   `/ptest` acknowledgement comment authored by `github-actions[bot]`, ignoring
   comments from other workflows that post as the same account, and refuses to run if the
   PR head has moved since the request. Like `pull-request.yml`, it builds and
   tests the PR merge commit.

The build and tests execute code from the PR on repository runners. Review the
code before running the command. `test-slash-command.yml` must exist on the
default branch. `ADD_TO_PROJECT_PAT` must be able to read organization
membership, including private memberships (`read:org` for a classic PAT,
authorized for SSO if required), and to add and remove labels on PRs. A label
added with `GITHUB_TOKEN` would not trigger the second workflow.

## Go Get (`go-get.yml`)

Go Get can be used to automate updating Go modules in this repository. It will run `make go-get` which is a helper script for running `go get -d $GOGET_MODULE@$GOGET_VERSION` in all needed places, commit and create a pull request.

If `Username of the source for this workflow run` is set, the username will be mentioned in the pull request and configured as assignee. This was added for automated workflows, where the user and URL can be used to link back to the source of the trigger.

If `URL of the source for this workflow run` is set, the URL will be mentioned in the pull request. This was added for automated workflows, where the user and URL can be used to link back to the source of the trigger.

## Create doc issue (`create-doc-issue.yml`)

Organization members can comment `/create-doc-issue` on an issue (not a pull request) to create a documentation issue in the same organization's `rancher-product-docs` repository, or `prime-docs` if the original issue has the `prime` label. The new issue's title is prefixed with `document:`, and its body contains the original issue's link followed by `More information to be added upon request.`

The workflow uses `CREATE_DOCS_PAT`, which needs permission to read organization membership and create issues in both documentation repositories and comment on the original issue. To detect private members, the PAT must belong to an organization member and have the `read:org` scope. If the organization uses SAML SSO, authorize the PAT for the organization. The membership check returns `404` both when the actor is not a member and when the token cannot see a private member, so these requirements are necessary for private members to be detected.

The workflow copies the milestone by matching its title in the target repository and comments on the original issue with the new issue's link. If the milestone is missing in the target repository, it creates the issue without one and notes this in the confirmation comment.
