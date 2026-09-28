# Tools: check first, reproduce deliberately

These publication helpers use Python's standard library. They do not call a model, send traffic, install dependencies or start VMs. Run them from the repository root with Python 3.11 or later.

| Tool | Purpose | Does it write? |
|---|---|---|
| `verify_repository.py` | Check published file hashes, Markdown folder guidance, current documentation links and the main README's visibility | No |
| `check_release_assets.py` | Check all six archive identities, destinations, instructions and publication-link status | No |
| `check_publication_scope.py` | Detect withheld manuscript/image/document formats, including nested ZIP members | No |
| `build_result_views.py --check` | Recompute final CSV/JSON/Markdown views in memory and compare saved outputs | No |
| `analyze_model_reviews.py --check` | Recompute the supplied two-model consistency comparison | No |
| `recompute_packet_evidence.py` | Recalculate all packet episode metrics and condition contrasts from the saved raw archives | No |
| `prepare_workspace.py` | Extract a verified frozen source snapshot into a new, separate experiment workspace | Only a new workspace and preparation receipt |

`packet_recompute_core.py` supports the packet checker. It retains the prior independent audit's cohort definitions and checks transport accounting, settings, measured outcomes, action/restore records and topology readback. The wrapper also checks asset hashes and compares every condition aggregate and paired contrast with the supplied audit. This is saved-data analysis, not a new packet run.

Without `--check`, the two view builders update their own derived result files. That mode is for maintainers updating the reproducibility package; it never changes source evidence. After approved changes, rebuild the release manifest through the author release process. Do not present a changed package as the previous byte-identical release.

Start with the [reproduction guide](../docs/03_reproduce.md). Supporting integrity records now live in [release/](../release/README.md); the tools locate them automatically, so the commands above remain unchanged. A complete local handoff includes large evidence ZIPs. A Git source clone may omit those assets: `verify_repository.py --without-raw-assets` explicitly labels that check as partial if any assets are absent.

For a deeper archive check, run `python tools/verify_repository.py --deep-assets`. It reads each scientific member through the public member manifest without extracting anything. This processes several gigabytes of uncompressed measurements. Added archive READMEs are declared in the member manifest and bound by the outer ZIP hash; the verifier does not mislabel them as original scientific files.

The frozen experimental implementations remain in [code](../code/README.md). These small helpers make the paper-facing evidence easier to navigate; they do not replace the scientific implementations.

The current catalogue provides download links for all six companion assets. Use `python tools/check_release_assets.py --require-published` to check their declared availability and recorded identities. The tool also supports explicitly pending links when maintainers prepare a future release, but that is not this catalogue's current status. A successful catalogue check does not test remote downloads. After downloading, use the file verifier to check the bytes.
