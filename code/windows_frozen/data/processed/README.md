# Processed data directory

Reproducible, de-identified incident summaries derived from the raw dataset are
written here. Generated files are excluded from Git by default until they have
been reviewed for licensing, privacy, and accidental identifiers.

`scripts/prepare_netslab_contexts.py` verifies the extracted database against
the extraction-receipt SHA-256, aggregates every label stratum, and marks the
frozen replay strata. It does not export row-level data or identifier values.
