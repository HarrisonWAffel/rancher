#!/usr/bin/env bash
#
# Reports failing nightly-provisioning-tests.yml jobs per branch, and builds the Slack
# webhook payload used for alerting. We check branches listed in the provisioning-test-scopes.yaml's
# explicit.nightly.meta.branches list.
#
# For each branch, only a run's 3rd attempt (by default) counts as a real failure, and only if
# that run was started by the nightly scheduler itself (github-actions[bot]), not someone
# manually re-running it.
#
# Writes to GITHUB_OUTPUT:
#   any-failures=true|false
#   slack-payload=<JSON>   (only written when any-failures is true)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_FILE="${SCOPES_CONFIG:-$SCRIPT_DIR/provisioning-test-scopes.yaml}"
WORKFLOW_FILE="${NIGHTLY_WORKFLOW_FILE:-nightly-provisioning-tests.yml}"

GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/stdout}"
HOURS_AGO="${HOURS_AGO:-9}"
NIGHTLY_TEST_FAILURE_LIMIT=${NIGHTLY_TEST_FAILURE_LIMIT:-3}

# Supports both the macos and linux `date` command
# so that this script can be run locally in any env
if date -v-"$HOURS_AGO"H >/dev/null 2>&1; then
  FORMATTED_HOURS_AGO="$(date -u -v-"$HOURS_AGO"H +%Y-%m-%dT%H:%M:%S)"
else
  FORMATTED_HOURS_AGO="$(date -u -d "$HOURS_AGO hours ago" +%Y-%m-%dT%H:%M:%S)"
fi

echo "Checking for Nightly Failures Since $FORMATTED_HOURS_AGO" >&2

if [ ! -f "$CONFIG_FILE" ]; then
  echo "error: config not found: $CONFIG_FILE" >&2
  exit 1
fi

if ! command -v yq >/dev/null; then
  echo "error: yq (v4) is required" >&2
  exit 1
fi

# Space-separated list of branches to check, e.g. "main release/v2.15 release/v2.14"
TARGET_BRANCHES=$(yq -o=json '.explicit[] | select(.name == "nightly") | .meta.branches' "$CONFIG_FILE" | jq -r '.[]' | paste -sd ' ' - )

echo "Checking target Branches [$TARGET_BRANCHES]" >&2

blocks=$(jq -n \
  --arg failure_limit "$NIGHTLY_TEST_FAILURE_LIMIT" \
  '[
    {
      type: "header",
      text: { type: "plain_text", text: ("🚨 Nightly Provisioning Test Failures (after " + $failure_limit + " attempts)"), emoji: true }
    },
    { type: "divider" }
  ]')

# Each failing branch needs its own numbered container block_id (container-1, container-2, ...)
container_index=0

any_failures="false"

for branch in $TARGET_BRANCHES; do
  echo "Checking $branch..." >&2

  # IDs of completed runs, on this branch, in the last $HOURS_AGO hours, that failed.
  failing_run_ids=$(gh run list \
    --repo "$GITHUB_REPOSITORY" \
    --workflow="$WORKFLOW_FILE" \
    --branch "$branch" \
    --status completed \
    --limit 50 \
    --json databaseId,attempt,conclusion \
    --created "${FORMATTED_HOURS_AGO}..*" \
    --jq "[.[] | select(.conclusion == \"failure\" and .attempt == $NIGHTLY_TEST_FAILURE_LIMIT)] | .[].databaseId")

  # Limit results to workflow runs initiated by the nightly executor
  run_id=""
  for candidate_id in $failing_run_ids; do
    echo "Checking if $candidate_id was triggered by the correct bot actor" >&2
    triggering_actor=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${candidate_id}" --jq '.triggering_actor.login')
    if [ "$triggering_actor" = "github-actions[bot]" ]; then
      run_id="$candidate_id"
      break
    fi
  done

  if [ -z "$run_id" ]; then
    echo "Found no failing run_ids in the past $HOURS_AGO hours for branch $branch" >&2
    continue
  fi

  echo "Nightly run $run_id failed on branch $branch after $NIGHTLY_TEST_FAILURE_LIMIT attempt(s)" >&2

  any_failures="true"
  run_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${run_id}"

  # JSON array of failing job names (e.g. "k3s, ^Test_(General|Provisioning|Fleet)_.*$")
  failing_job_names=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/jobs" \
    --jq '[.jobs[] | select(.conclusion == "failure") | .name]')

  # Add each job as an entry in a simple bullet list
  failing_job_list=$(echo "$failing_job_names" | jq -r 'map("• `" + . + "`") | join("\n")')
  failing_job_count=$(echo "$failing_job_names" | jq 'length')

  container_index=$((container_index + 1))

  # Represent each failing branch as a single collapsible container block.
  # It is collapsed by default so a lot of failing jobs can't create a massive message
  branch_blocks=$(jq -n \
    --arg branch "$branch" \
    --arg job_count "$failing_job_count" \
    --arg job_list "$failing_job_list" \
    --arg run_url "$run_url" \
    --arg idx "$container_index" \
    '[
      {
        type: "container",
        block_id: ("container-" + $idx),
        title: { type: "plain_text", text: ($job_count + " job(s) failed on " + $branch) },
        is_collapsible: true,
        default_collapsed: true,
        child_blocks: [
          {
            type: "rich_text",
            block_id: ("intro-" + $idx),
            elements: [
              {
                type: "rich_text_section",
                elements: [ { type: "text", text: "The following test cases failed" } ]
              }
            ]
          },
          {
            type: "section",
            block_id: ("jobs-" + $idx),
            text: { type: "mrkdwn", text: $job_list }
          },
          {
            type: "actions",
            elements: [
              { type: "button", text: { type: "plain_text", text: "View run" }, url: $run_url }
            ]
          }
        ]
      }
    ]')

  blocks=$(echo "$blocks" | jq --argjson new_blocks "$branch_blocks" '. + $new_blocks')
done

echo "any-failures=${any_failures}" >> "$GITHUB_OUTPUT"

if [ "$any_failures" != "true" ]; then
  exit 0
fi

slack_payload=$(jq -n --argjson blocks "$blocks" '{ blocks: $blocks }')

echo "slack-payload=${slack_payload}" >> "$GITHUB_OUTPUT"
