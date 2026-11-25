# Inspect upstream changes

Dispatch **Inspect deep runtime upstream changes** with a full upstream smolvm commit. The workflow records the exact commits and trees for the three repositories and keeps the independently observed upstream library tips separate from the candidate's committed gitlinks. It uploads a JSON report with changed paths, downstream patch overlaps, possible replacements and affected acceptance gates.

For a local report, fetch the candidate and its two committed library revisions into existing Git object stores and run the same comparison.

```bash
python3 scripts/deep/upstream-sync.py --smolvm "$SOURCE" \
  --downstream "$DOWNSTREAM_SHA" --upstream "$UPSTREAM_SHA"
```

Keep `patch-registry.json` current when adding or removing a downstream contract. A matching patch ID gives a candidate for removal. Verify the contract and run the recorded gates, including the retained reader corpus, before dropping the downstream change in an isolated candidate branch. Build and canary that branch through the existing source and Bundle workflows. Running and stored instances keep their pinned releases.
