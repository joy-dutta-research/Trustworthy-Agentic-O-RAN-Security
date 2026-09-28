# Blinded label review

Do not use filenames or identifiers from the generated conformance suite as
review IDs: they contain category hints. For the first export, create a private
key and mapping:

```bash
python scripts/export_label_review.py \
  --output review/private/reviewer-a.csv \
  --mapping-output review/private/review_mapping.json \
  --create-blind-key
```

Create the second sheet with the same key but without `--create-blind-key`:

```bash
python scripts/export_label_review.py \
  --output review/private/reviewer-b.csv
```

Give each reviewer only their CSV. Withhold the key, mapping, implementation
outputs, generated expectations, and the other review until both reviewers have
finished. The export uses keyed opaque review/action/approval IDs while leaving
the substantive policy facts visible.

Compare the completed sheets with:

```bash
python scripts/compare_label_reviews.py \
  review/private/reviewer-a.csv \
  review/private/reviewer-b.csv \
  --output review/private/agreement.json
```

Archive the mapping and agreement evidence only after labels and adjudication
are frozen. The entire `review/private/` directory is ignored by Git by default.
