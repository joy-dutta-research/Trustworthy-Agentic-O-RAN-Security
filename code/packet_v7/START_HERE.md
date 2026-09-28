# Home-machine handoff: start here

This is a portable research package, not an installed VM and not a result.
Its purpose is to run the **first measured, isolated Linux packet pilot** and
return auditable evidence to the original research conversation. Existing
offline conformance studies and two model reviews are already completed.

## The shortest route

1. Copy this ZIP and its `.zip.sha256` companion to your home computer. Verify
   the SHA256 before extracting into a new local folder. Keep the original ZIP.
   Avoid OneDrive/network-synced folders for VM disks or measurements.
2. Open the extracted `oran-home-lab` folder in your locally connected coding
   assistant. Paste **HOME_ASSISTANT_PROMPT.txt** into a new conversation.
   Choose your requested GPT-6 Astra / Ultra setting if your account offers it;
   record what is actually displayed. The experiment does not call that model.
3. Let the assistant inventory the home machine read-only first. Approve only
   scoped setup steps after review. A Windows administrator account is helpful,
   but does not establish that Hyper-V is available or that firmware
   virtualization is enabled. Do not disable the assistant's sandbox globally.
4. Follow **docs/HOME_MACHINE_RUNBOOK.md**: prepare a new Ubuntu Server VM,
   transfer the package offline, qualify the guest, and run a bounded pilot.
   You will still need to approve the new virtual disk and privately enter a
   guest password. A chat without local computer/terminal tools can guide you,
   but cannot itself install a VM on your computer.
5. Export the results using the supplied command, transfer the resulting ZIP
   and checksum back to Windows, and upload that ZIP to the original
   conversation. **Send unsuccessful runs too.** No need to send the whole VM.

## Included

- Frozen original gateway/configuration and portable Python reference code.
- Original synthetic conformance fixtures and a de-identified aggregate only.
- Closed-loop controller, Linux packet harness, scoring, and unit tests.
- Official Ubuntu download verification and guarded Hyper-V creation helpers.
- Offline transfer-disk helper with explicit owner confirmation checkpoints.
- Qualification/pilot wrapper and all-session results exporter.
- Experiment context, protocols, safety boundaries, and handoff instructions.
- BUNDLE_MANIFEST.json with a hash and byte size for every delivered file.

## Deliberately not included

Raw intrusion datasets, unpublished papers, private reviewer mappings and
responses, university credentials, API keys, account settings, VM disks,
or the approximately 4 GB Ubuntu installer. The official installer is downloaded
and authenticated at home. No OpenAI/Gemini API key or GPU is required.

## Honest boundaries

The first run is a deterministic-controller **pilot**, not a live LLM planner,
IDS accuracy study, radio/E2 testbed, or final confirmatory journal experiment.
The home assistant should complete qualification and the pilot, then return
all evidence. The original conversation will assess failures, variability,
needed corrections and the next frozen evaluation before final paper claims.

Source ZIP checksums detect copying errors; they are not a digital signature or
proof of safety. Review scripts before elevated execution. Human approval of
policy assumptions and final manuscript claims is still required.
