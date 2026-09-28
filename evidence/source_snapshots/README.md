# Public source snapshots

We provide two verified transport copies for preparing a clean experiment workspace:

| Archive | Purpose |
|---|---|
| `ORAN_WORKSTATION_PUBLIC_v1.zip` | Frozen Windows Stages 0–5 implementation, settings, tests and constructed inputs |
| `ORAN_PACKET_V7_PUBLIC_v1.zip` | Packet v7 implementation used in both successful 36-episode runs |

These public packages omit the legacy `docs/paper/closed_loop_experiment.tex` manuscript-writing template. We also omit that template from the nested historical Stage 6 bootstrap inside the Windows package. No executable source, configuration, test, measurement or constructed input has been edited. The nested bootstrap keeps its original filename because the frozen packaging code requires that path; its new checksum and omission record identify it as a public transport copy.

The archive and transport-manifest hashes therefore differ from the original deliveries. [PUBLIC_SOURCE_OMISSIONS.json](PUBLIC_SOURCE_OMISSIONS.json) records the original and public identities, exact omissions, changed packaging members and every unchanged scientific source member. We retain the byte-identical originals privately outside the public repository. Historical experimental evidence keeps its original identities, rather than being relabelled as an experiment performed with the public package.

The preparation tool checks the pinned public archive and every manifest member before extracting a fresh workspace. The regenerated manifests remain compatible with the unchanged frozen bundle-verification tools. These are packaging checks, not new experimental results.

Original prompts, README text and VM scripts inside these archives are historical provenance, not instructions to execute on your current computer. Follow the new root guide and explicitly authorize any isolated laboratory operation. Both exact third-party dataset inputs are obtained separately; they are not inside these snapshots.
