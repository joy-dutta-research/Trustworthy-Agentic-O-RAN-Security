# Stage 6: packet action and feedback

Our packet experiment connects policy checking to observable service outcomes. We retain all methods and all three scenarios below, for the first VM and its clean-VM repeat, both on Workstation 2. The result is exploratory: **three paired episode repetitions per condition per VM**. Packets are measurements within an episode, not independent experimental repetitions.

**Persistent flood:** the three intervention methods improved protected timely delivery from about 29% without action to about 73%. Evidence + feedback retained this benefit; the data do not establish superior flood mitigation over the other intervention methods. Delivery did not fully recover during the event: the six-second action expired while the flood continued, and the protocol allowed one intervention.

**Transient benign burst:** evidence + feedback abstained in all three repetitions per VM. Fixed rule and policy gate intervened in all three, reducing the legitimate suspect client's echoed goodput by approximately 99–100 kbit/s. Avoiding this unnecessary restriction illustrates the value of corroborating fresh, target-bound evidence beyond policy permission.

**Acknowledged but ineffective action:** feedback recognized no observed benefit and requested restoration/local operator review in all three repetitions per VM. Protected delivery did not improve. Because the injected action was a no-op, this demonstrates outcome monitoring and an escalation/restoration trigger, not recovery from harmful actuation or a tested human response service.

## How the measurements work

Four Linux namespaces represent a protected UDP client, suspect client, router and echo server, with a 1,000-kbit/s bottleneck. Each episode lasts 20 s; the event cohort is requests sent in seconds [4,14). Payloads are 512 bytes; protected traffic is 100 packets/s, suspect background 120 packets/s, flood 400 packets/s, and the benign high-rate burst lasts 0.6 s. The action requests an 80% reduction for 6 s. The order seed 220926 randomizes job order only.

Protected timely delivery is the percentage of event-cohort requests receiving an echo within 500 ms, retaining lost/late requests in the denominator. Suspect goodput is echoed **application payload** in decimal kbit/s over the event window, not router ingress rate. RTT p95 is conditional on received echoes and must not be used alone to describe delivery quality.

`episode_outcomes.csv` / `.json` contains all 72 episodes. `condition_means` contains all 24 means. `paired_contrasts` contains all 18 method-minus-no-action contrasts; positive timely-delivery differences are percentage points, not relative percent gains. Its individual-delivery-difference list preserves the original execution order. `paired_episode_contrasts` gives the same differences as 54 explicitly keyed VM/scenario/method/replicate rows, with sources for both paired episodes. No packet-level confidence intervals or significance claims are introduced. `protocol.json` records settings, source identities and environments.

The action timestamp is recorded **before dispatch**, not at actuator acknowledgement. Feedback's extra observation interval is approximately one second; it is not processor overhead. Restoration-command time is not time to restore service. Both VMs ran on Workstation 2, the same physical computer. These are synthetic packet mechanisms, not real E2/radio integration, and the controller is deterministic rather than an LLM.

| Scenario | Method | First timely % | Repeat timely % | First suspect kbit/s | Repeat suspect kbit/s |
|---|---|---|---|---|---|
| persistent_flood | No action | 29.649 | 28.875 | 815.377 | 818.244 |
| persistent_flood | Fixed rule | 72.599 | 72.853 | 528.247 | 526.746 |
| persistent_flood | Policy gate | 72.844 | 72.979 | 526.609 | 526.609 |
| persistent_flood | Evidence + feedback | 72.439 | 72.920 | 529.203 | 527.019 |
| benign_burst | No action | 96.532 | 96.362 | 512.546 | 513.365 |
| benign_burst | Fixed rule | 96.392 | 96.427 | 413.423 | 413.559 |
| benign_burst | Policy gate | 96.394 | 96.462 | 413.969 | 413.150 |
| benign_burst | Evidence + feedback | 96.361 | 96.532 | 513.229 | 512.546 |
| ineffective_action | No action | 30.030 | 29.370 | 813.875 | 816.469 |
| ineffective_action | Fixed rule | 29.805 | 29.461 | 814.831 | 815.923 |
| ineffective_action | Policy gate | 29.356 | 29.771 | 816.469 | 814.694 |
| ineffective_action | Evidence + feedback | 29.208 | 28.972 | 817.015 | 817.971 |

## Paired differences from no action

| VM | Scenario | Method | Timely change pp | Suspect goodput change kbit/s |
|---|---|---|---|---|
| first | persistent_flood | Fixed rule | 42.949 | -287.130 |
| first | persistent_flood | Policy gate | 43.195 | -288.768 |
| first | persistent_flood | Evidence + feedback | 42.790 | -286.174 |
| first | benign_burst | Fixed rule | -0.140 | -99.123 |
| first | benign_burst | Policy gate | -0.138 | -98.577 |
| first | benign_burst | Evidence + feedback | -0.171 | 0.683 |
| first | ineffective_action | Fixed rule | -0.226 | 0.956 |
| first | ineffective_action | Policy gate | -0.674 | 2.594 |
| first | ineffective_action | Evidence + feedback | -0.822 | 3.140 |
| repeat | persistent_flood | Fixed rule | 43.979 | -291.499 |
| repeat | persistent_flood | Policy gate | 44.104 | -291.635 |
| repeat | persistent_flood | Evidence + feedback | 44.046 | -291.226 |
| repeat | benign_burst | Fixed rule | 0.065 | -99.806 |
| repeat | benign_burst | Policy gate | 0.100 | -100.215 |
| repeat | benign_burst | Evidence + feedback | 0.170 | -0.819 |
| repeat | ineffective_action | Fixed rule | 0.091 | -0.546 |
| repeat | ineffective_action | Policy gate | 0.401 | -1.775 |
| repeat | ineffective_action | Evidence + feedback | -0.398 | 1.502 |

[Column meanings and units](DATA_DICTIONARY.md)

[Results guide](../README.md) · [Previous stage](../05_scaling_and_load/README.md) · [Next stage](../07_reproducibility/README.md)
