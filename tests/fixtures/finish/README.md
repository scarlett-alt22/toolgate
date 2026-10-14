# finish three-arm offline fixtures

This input set is cut from the real positive arm in `evidence-loop/normal/`, for
`python3 tests/finish_arms.py` to recompute `finish.py`'s results with zero API calls.

`base/` keeps the positive arm's events that matter to `finish.py`'s verdict: three
forwarded 2xx requests, three closed scan terminals, one unique tool use/result causal
pair, and the complete snapshot phase. So the fixtures can be rerun independently at
different times, the shared base does only two normalizations:

- deletes the already-present `finished` events and `terminal.json`, so `finish.py` can
  close out again;
- sets `plan.json`'s `state_before` to an empty object, so the current hashes of this
  machine's five volatile state files don't affect these fixtures, which only test
  finish's three-way logic.

`cases.json` declares five arms. Each counter-arm varies exactly one semantic variable;
the script strictly checks old values, match counts, and the changed-file set, then calls
`finish.py`:

1. `baseline`: input unchanged, expects `success`.
2. `scan_outcome_failed`: one scan terminal's `outcome` goes from `ok` to `failed`.
3. `truncated_stream`: a scan terminal that still has tool-use causal evidence becomes
   `failed/truncated_stream`.
4. `causal_evidence_absent`: deletes the tool use/result causal event pair; scans are
   still all `ok`.
5. `upstream_non_2xx`: one request's `upstream_status` goes from 200 to 500.

Variants materialize in a temp directory; the committed `base/` plus `cases.json` fully
determine each cell's input.
