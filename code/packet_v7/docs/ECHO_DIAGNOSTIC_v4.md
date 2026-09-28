# Bounded UDP echo diagnostic v4

This new source release instruments the existing server echo call without retry,
socket tuning, extra traffic, changes to load/scoring, or removal of failures.
Record exception type/errno, sequence, sender timestamp, echo-start/end times,
socket timeout/buffer sizes, all error counts and at most 32 detailed failures.
Unexpected errors still propagate. No network, package or security change.

First run fresh qualification. Then run exactly three fixed 20-second
ineffective_action/fixed_rule diagnostic episodes (replicate IDs 0,1,2).
The original scorer still rejects echo errors. Retain each technical error and
continue only through this predetermined diagnostic budget after verified cleanup.
Stop on uncertain cleanup/source/worker exceptions; no episode retry or extension.
If no error reproduces, report inconclusive. No scientific success claim.
Fixed upper limits: qualification 900 s; diagnostic phase 300 s; all evidence
under 480 MiB; transfer remains the approved 1 GiB disk. All prior releases,
including the failed v3 pilot, remain immutable.
