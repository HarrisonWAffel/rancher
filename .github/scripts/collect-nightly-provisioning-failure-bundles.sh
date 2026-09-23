#!/usr/bin/env bash
#
# Iterates over the most recent nightly provisioning tests workflows (past 9 hours) and
# identifies which ones have failed. For each failing branch, the latest test output XML file
# is downloaded and used to create a single failure bundle.json file. We check branches listed in the provisioning-test-scopes.yaml's
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
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-rancher/rancher}"
GITHUB_OUTPUT="${GITHUB_OUTPUT:-/dev/stdout}"
HOURS_AGO="${HOURS_AGO:-9}"
NIGHTLY_TEST_FAILURE_LIMIT=${NIGHTLY_TEST_FAILURE_LIMIT:-3}

log() {
  echo "[nightly-prov-report] $*" >&2
}

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
any_failures="false"

all_bundles=()

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
  head_sha=""
  for candidate_id in $failing_run_ids; do
    echo "Checking if $candidate_id was triggered by the correct bot actor" >&2
    run_details=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${candidate_id}")
    triggering_actor=$(jq -r '.triggering_actor.login' <<< "$run_details")
    if [ "$triggering_actor" = "github-actions[bot]" ]; then
      run_id="$candidate_id"
      head_sha=$(jq -er '.head_sha | select(type == "string" and length > 0)' <<< "$run_details") || exit 1
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
  run_dir="./${branch}-${run_id}-artifacts"
  mkdir -p $run_dir

  # Download the raw XML output of the failing run. This artifact includes the specific tests
  # and logs for failing tests.
  artifact_ids="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/artifacts?per_page=100" \
    --jq '[.artifacts[] | select(.expired == false and .name == "XML Results")]
          | sort_by(.created_at) | .[].id')"

  # TODO: Do we need a loop or does name overwriting mean we only have access to the latest iteration?
  while IFS= read -r artifact_id; do
    artifact_dir="${run_dir}/set-${run_id}"
    [ -n "$artifact_id" ] || continue
    zip_file="${artifact_dir}.zip"
    mkdir -p "$artifact_dir"
    gh api -H "Accept: application/vnd.github+json" \
      "repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip" > "$zip_file"
    unzip -oq "$zip_file" -d "$run_dir"
    rm -rf "$artifact_dir" "$zip_file"
    log "artifact $artifact_id downloaded"
  done <<<"$artifact_ids"

  # JSON array of failing job names (e.g. "k3s, ^Test_(General|Provisioning|Fleet)_.*$")
  failing_job_names=$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/jobs" \
    --jq '[.jobs[] | select(.conclusion == "failure") | .name]')

  # One time conversion of xml -> json
  files=()
  for file in "$run_dir"/*; do
    if [ -f "$file" ]; then
      if [[ "$file" == *.xml ]]; then
        yq --xml-attribute-prefix="" -p=xml -o=json "$file" > "${file%.xml}.json"
        files+=("${file%.xml}.json")
      fi
    fi
  done

  # For all json files, look for failing test cases and associate them
  # with the failing job (via file naming conventions). Failing jobs that have
  # no matching test case entry (no report uploaded, crashed before tests ran,
  # integration tests, etc.) get a placeholder entry, so that no failing job is ever dropped.
  failing_tests=$(jq -n \
    --argjson jobs "$failing_job_names" \
    --arg branch "$branch" \
    --arg run_url "$run_url" \
    --arg head_sha "$head_sha" \
    '
    # A lone <testsuite>/<testcase> element without siblings is emitted as a
    # bare object (not an array) by the xml conversion, so wrap it before
    # iterating.
    def asarray: if type == "array" then . else [.] end;

    # The xml conversion emits element text under a "+content" key, we need to rename it.
    def clean_failure:
      if type == "object"
      then with_entries(if .key == "+content" then .key = "content" else . end)
      else .
      end;

    # The failing job a report belongs to is the first failing job whose name
    # mentions both the distribution and the suite, else "dist, suite".
    def matched_job($report):
      (
        [
          $jobs[]
          | select(
              ascii_downcase | contains($report.dist | ascii_downcase)
              and (sub("Test"; "") | gsub("[()|_^.*$]"; "") | contains($report.suite))
            )
        ]
        | first
      )
      // ($report.dist + ", " + $report.suite);

    # One entry per failing test case found in the downloaded reports.
    [
      inputs
      | (input_filename | split("/")[-1]
         | capture("^report-(?<dist>[^-]+)-(?<suite>.*)\\.json$")) as $report
      | ((.testsuites.testsuite // empty) | asarray)[]
      | select(.failures != "0")
      | ((.testcase // empty) | asarray)[]
      | select(.failure != null)
      | {
          job: matched_job($report),
          name,
          classname,
          time,
          failure: .failure | clean_failure
        }
    ] as $tests
    | ($jobs - ($tests | map(.job))) as $uncovered
    | {
        branch: $branch,
        run_url: $run_url,
        head_sha: $head_sha,
        failures: (
          $tests
          + [
              $uncovered[]
              | { job: ., name: null, classname: null, time: null, failure: null }
            ]
        )
      }' "${files[@]}")

  bundle_file="${run_dir}/${branch//\//-}.json"
  echo "$failing_tests" > "$bundle_file"
  all_bundles+=("$bundle_file")
done

# Produce a final JSON array where each entry is named
# after the branch the tests failed on.
# e.g.
# {
#    "main": {
#      "branch": "main",
#      "run_url": "https://github.com/rancher/rancher/actions/runs/35821850565",
#      "head_sha": "1a7ed5e31da56631a05a5e8cbf44c428d0945068",
#      "failures": [
#        ...
#       ]
#     }
# }
complete_bundle=$(jq -n '
  reduce inputs as $bundle (
    {};
    .[(input_filename | split("/")[-1] | sub("\\.[^.]+$"; ""))] = $bundle
  )
' "${all_bundles[@]}")

echo "$complete_bundle" > bundle.json
echo "any-failures=$any_failures" >> "$GITHUB_OUTPUT"
