# Evaluation manifests

Do not commit malware samples or confidential binaries to this repository. Keep the corpus in a controlled local lab and create a CSV manifest like:

~~~csv
path,label,family
samples/known-good-tool.exe,benign,
samples/family-a-variant-01.exe,malicious,family-a
samples/family-a-variant-02.exe,malicious,family-a
samples/family-b-sample.elf,malicious,family-b
~~~

Paths may be absolute or relative to this CSV. Labels must be exactly benign or malicious. Use family labels to expose family-specific blind spots. Keep train/tuning/holdout corpora separated by malware family and collection source when assessing future models; near-duplicate variants must not leak across splits.

Run:

~~~sh
python3 qsafe_eval.py data/manifest.csv --threshold 40 --json reports/evaluation.json
~~~

The score threshold is a heuristic decision point, not a calibrated probability. Report the corpus source, collection date, class balance, family coverage, duplicate policy, and skipped files alongside metrics. Use a held-out corpus before making detection-rate claims.
