# Continuous integration scope

`checks.yml` runs on ordinary Ubuntu and Windows GitHub workers after a future approved push. It checks the source-only package, regenerates the saved result views in memory and tests safe helper behavior. It also extracts the canonical Windows source snapshot into a fresh working directory and runs its software tests; this is not the Windows performance campaign.

The large evidence release assets are not downloaded automatically. A source-only integrity check therefore reports which assets were not checked. The full handoff can be verified locally with those assets present. Real packet tests require a separately authorized isolated Linux VM and are never part of this workflow.

Third-party actions are pinned to full commit identities. Maintainers should review upstream updates deliberately rather than silently following moving action tags.
