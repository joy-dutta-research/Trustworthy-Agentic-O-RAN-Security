# Awake setup first; long experiments afterward

The owner wants to resolve permissions and interactive VM steps before going
to sleep. This changes the operational order, not the frozen scientific methods.
Orders 0-5 still use the same experimental code, policy, seeds and workload as
the university campaign. New scripts orchestrate, verify and report those runs.

## First conversation on the destination

Do not immediately start the long Windows benchmarks. First verify both ZIPs
and inspect the actual machine read-only. Then present ONE concise checklist
of the actions that this host really needs. Obtain specific approval for each
applicable item, with exact new resource names, paths, disk sizes and boundaries:

- trusted software/Ubuntu media downloads and any missing host/guest packages;
- Windows Hyper-V feature enablement and a planned restart, if necessary;
- firmware changes, only if required, with the owner performing them;
- creation of the new isolated lab VM and, if agreed, a separate clean-repeat VM;
- creation and formatting of ONLY newly created, identity-checked lab virtual
  disks, including the offline transfer disk; never an existing physical disk;
- the validated offline source-update and result-return mechanism;
- guest-only privileged network-namespace experiments under the frozen resource,
  traffic, timeout and cleanup bounds; no real network or production interfaces;
- VM power-off at the agreed boundaries and sequential Windows measurements;
- the final study's fixed replication, runtime/disk budget and analysis plan,
  once technical qualification/pilot evidence is available.

Explain any unexpected requirement before acting. Do not ask for unrestricted
admin rights for the whole assistant, stored passwords, disabled protections,
permanent networking, automatic publication or automatic deletion. Approval in
the original conversation does not satisfy UAC/tool approvals on this computer.

## Finish the interactive parts while the owner is present

1. Complete approved installations/restart and verify the workstation resumed
   with the correct workspace, source checksums and private data imported.
2. Create/install the isolated Ubuntu VM. The owner confirms the new guest disk
   and enters local passwords privately. Complete provisioning before removing
   any explicitly approved temporary provisioning connection.
3. Establish a **tested** execution and evidence-return path for the NIC-free
   guest. Windows terminal access is not automatically guest access. If the
   assistant cannot control the guest, arrange and test a bounded guest batch
   run that the owner starts locally, or a separately reviewed non-network
   control mechanism. Never enable SSH/RDP, add a NIC or bypass authentication
   just to claim unattended operation.
4. Perform qualification and the short technical pilot early. Complete any
   final-harness development/deployment that still requires owner console input.
   Freeze the final protocol and obtain the relevant author/resource approvals.
   Pilot evidence may reveal a question that could not be known at startup.
5. Prepare and test the clean-repeat source/environment and transfer steps while
   the owner is available. The source, protocol and seeds must stay frozen.

## The unattended-readiness checkpoint

Before telling the owner they can leave, write a local
`results/local/stage6_runs/campaign_summary/UNATTENDED_READINESS.json` and a short
human-readable checklist. State each item's verified status and evidence:

- installation/restart/guest credential entry completed;
- required permissions granted within exact resource scope;
- zero-NIC isolation and guest execution path tested;
- final source/version/protocol and fixed budget approved;
- fresh output locations, time/memory/disk guards, failure logging and cleanup tested;
- owner-free execution AND result collection tested, or the specific remaining
  console step prominently identified;
- clean-repeat plan ready without unapproved disk or network changes;
- Windows benchmark periods will run with the VM stopped;
- host awake/AC-power arrangements agreed without silently changing power/security
  policy, and tool-session availability understood.

Only mark READY when these are actually demonstrated. Otherwise state NOT_READY
and the exact remaining input. Administrative access alone is not evidence of
unattended readiness. An initial group of approvals cannot guarantee that no
new approval or reboot will be needed. Do not promise a flawless overnight finish.

Once ready, continue the approved tasks serially. Packet final/clean-repeat runs
may be prioritized first if their guest batch is ready; Windows Orders0-5 can
run before or afterward with Ubuntu stopped. Do not run CPU/disk-intensive
benchmarks concurrently with VM measurements. Order7 comparison closes after
the required evidence exists; its final verification cannot precede those data.

On any new safety/permission requirement, stop the affected work, safely clean
up only owned lab objects and retain a partial receipt. Continue only unrelated
already authorized work where safe. Never fabricate completion or loosen a
bound to avoid waking the owner. Return export still requires the owner's
privacy review; local results may remain ready until they return.

