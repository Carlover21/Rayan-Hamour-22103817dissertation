# CAN/DoIP In-Vehicle Network Simulation with Rule-Based IDS

Software simulation supporting the dissertation *"Detecting Cybersecurity
Attacks in In-Vehicle Networks Using CAN and DoIP Simulation"*. Models a
small in-vehicle CAN bus with several virtual ECUs, a conceptual DoIP
gateway representing the IP-connected diagnostic attack surface, a
rule-based intrusion detection system, and an evaluation harness that
scores detection rate and false positives.

No real vehicle hardware, SocketCAN, or network sockets are used - CAN is
simulated via python-can's virtual interface, and DoIP is a mocked,
in-process model (per the proposal's scope: conceptual, not full ISO 13400).

Everything in this file describes `src/carnet`, the package the evaluation
chapter's numbers come from. `dashboard/` is a separate, simplified,
tick-based engine built purely for live visual demonstration (see its own
docstrings) - it is not evaluation evidence and intentionally does not share
code with `src/carnet`.

## Project structure

```
src/carnet/
  config.py          shared ECU topology, IDS/SecOC/bus-off thresholds, DoIP addressing
  can/
    ecu.py           VirtualECU - a periodic CAN transmitter (optionally SecOC-protected)
    bus.py           virtual bus + notifier helpers
    traffic.py       TrafficGenerator - spins up all "normal" ECUs
    logger.py        CANLogger - records every frame (memory + CSV)
  doip/
    message.py       DoIPMessage / DoIPPayloadType
    gateway.py        DoIPGateway - routing activation + CAN forwarding, mocked
  security/
    secoc.py           simplified SecOC: per-ID derived keys, truncated HMAC + freshness counter
  attacks/
    flood.py             flooding / DoS
    spoof.py             identifier spoofing
    doip_injection.py    unauthorized/abused CAN injection via DoIP
    busoff.py             bus-off / transmit-error-counter attack
    infotainment_pivot.py attacker entry via a compromised infotainment/telematics unit, not DoIP
    key_fob_relay.py       single-shot relayed-unlock-command attack
    scenario.py             AttackScenario + uniform run_scenario() dispatcher
  ids/
    detector.py       RuleBasedIDS - unknown ID / rate / timing / SecOC-auth / silence rules
    anomaly.py          AnomalyIDS - IsolationForest-based ML detector, for comparison
    alert.py            IDSAlert record
  eval/
    harness.py         run_trial() - baseline + attack + scoring, both detectors optional
    sweep.py            intensity sweeps across repeats -> DataFrame/CSV
    plots.py             matplotlib output for the evaluation chapter
dashboard/              live browser dashboard (separate tick-based engine, see below)
tests/                  pytest unit tests (fast, no sleeps/timing)
run_demo.py                     single scenario, human-readable output + plot
run_evaluation.py               original proposal-scope sweep -> results/evaluation_results.csv
run_evaluation_extended.py      bus-off / infotainment / key-fob / SecOC / ML-comparison sweeps
```

## Setup

```bash
py -3.13 -m venv venv
venv\Scripts\pip install -e .
```

## Running

```bash
# One scenario at a time, with printed results and a traffic-timeline plot
venv\Scripts\python run_demo.py flood
venv\Scripts\python run_demo.py spoof
venv\Scripts\python run_demo.py doip

# Original proposal-scope evaluation (flood/spoof/doip only)
venv\Scripts\python run_evaluation.py

# Extended evaluation: bus-off, infotainment-pivot, key-fob-relay,
# SecOC with/without comparison, rule-based-vs-ML comparison
venv\Scripts\python run_evaluation_extended.py

# Live browser dashboard (visual demo only - see caveat above)
venv\Scripts\python -m dashboard.app
# then open http://127.0.0.1:5000/

# Unit tests
venv\Scripts\python -m pytest tests/ -v
```

## How the pieces fit together

1. **`TrafficGenerator`** starts one `VirtualECU` per entry in
   `config.ECU_PROFILE` that has a nominal period, each sending its
   arbitration ID on the shared virtual CAN bus with realistic jitter. This
   is the "normal baseline" from the proposal. If a `SecOCContext` is
   supplied, every frame is authenticated (truncated HMAC + rolling
   counter) before it goes on the bus.
2. **`DoIPGateway`** models the IP-reachable diagnostic entry point: a
   tester must first perform routing activation, after which diagnostic
   messages are forwarded onto the CAN bus as a real frame (ID `0x7E0`).
   Unauthorized attempts (no activation) are rejected and logged - this is
   itself a security control, separate from the CAN-side IDS. The gateway
   never holds any per-ID SecOC key, so anything it forwards fails
   authentication when SecOC is enabled, even if the attacker completed
   routing activation.
3. **Attacks** (`attacks/`) run concurrently with normal traffic. Beyond
   the original flood/spoof/DoIP-injection scope: **bus-off** exploits
   CAN's own transmit-error-counter state machine to silence a victim ECU
   entirely (Cho & Shin, CCS 2016); **infotainment-pivot** models an
   attacker who reaches the bus via a compromised head unit rather than
   DoIP at all, so the DoIP authorization gate never applies; **key-fob
   relay** models the CAN-visible effect of a passive-keyless-entry relay
   attack as a single low-frequency event, deliberately testing whether a
   rate/pattern-based IDS can catch a lone malicious message.
4. **`RuleBasedIDS`** listens to every frame and applies five independent,
   config-driven rules: unknown arbitration ID, rate threshold, timing
   deviation, SecOC authentication failure (only when SecOC is enabled),
   and silence (a periodic ID gone quiet far longer than its nominal
   period - the complementary case to rate threshold, and how bus-off
   attacks get caught).
5. **`AnomalyIDS`** is an alternative, ML-based detector (one
   scikit-learn `IsolationForest` per arbitration ID, trained on baseline
   traffic features) that `eval.harness.run_trial` can run in parallel with
   the rule-based detector, against identical traffic, for a fair paired
   comparison - each detector gets its own bus tap and dispatch thread so
   the ML detector's slower per-message inference can't distort the
   rule-based detector's timing measurements.
6. **`eval.harness.run_trial`** wires all of the above together for one
   scenario, and **`eval.sweep`** repeats it across attack intensities so
   the two `run_evaluation*.py` scripts can report how detection rate and
   false positives change under varying attack pressure and configuration
   (SecOC on/off, rule-based vs ML).
7. **`dashboard/`** is a separate Flask app with its own tick-based
   simulation engine (controllable virtual clock: pause/slow/fast/resume
   real-time), a small vehicle-dynamics model that turns decoded CAN
   signals into a car's on-screen position, and a live browser frontend
   (car/road view, instrument cluster, scrolling CAN traffic graph). It
   intentionally does not share code with `src/carnet` - it is a
   visualization/demo tool, not part of the evaluation pipeline.

## Key findings so far

- The original evaluation found a genuine rule-based-IDS blind spot: an
  attacker who completes DoIP routing activation like a legitimate tester,
  then abuses that access at a low rate (a handful of messages/sec), was
  **never** detected by the rate/timing rules alone, at any tested
  intensity - because the diagnostic ID has no periodic baseline to compare
  against, and its rate limit is tuned for much higher legitimate traffic.
- Enabling SecOC authentication closes that gap deterministically: because
  the DoIP gateway never holds a per-ID key, anything it forwards fails
  the `auth_invalid` check immediately, regardless of rate.
- The key-fob-relay attack (a single injected message, no flood) is largely
  *not* caught by either detector. The rule-based detector's timing rule
  only fires when the single event happens to land close enough in time to
  a legitimate message on the same ID (~25% detection rate over 8 trials,
  consistent with a geometric argument based on where in the ID's ~100ms
  period the injection lands); the ML detector did not catch it at all
  (0/8) with the current feature set (inter-arrival time + first two
  payload bytes). Both false negatives are honest findings, not bugs: a
  well-timed single malicious message is a real, hard case for both a
  threshold-based and an unsupervised-anomaly-based detector operating on
  this feature set, and the comparison is a useful counter to any assumption
  that "ML-based" automatically means "more robust."
- Flooding, spoofing, and the bus-off attack were caught reliably (100%) by
  both detectors, so the two approaches only really diverge on rare,
  single-shot events rather than on sustained/high-rate attacks.

## Known limitations (for the dissertation's limitations section)

- DoIP is a conceptual, in-process model (no real UDP/TCP sockets, no full
  ISO 13400 payload structure) - explicitly scoped this way in the proposal.
- SecOC here is a simplified illustration (truncated HMAC + rolling
  counter, one master key deriving per-ID keys), not a spec-accurate
  AUTOSAR SecOC implementation.
- The bus-off attack models the *outcome* of winning arbitration/forcing
  errors against a victim (an incrementing error counter crossing a
  threshold), not real CAN bit-level arbitration or error-frame physics -
  the underlying virtual bus has no electrical layer to model that on.
- A true RF relay attack (as opposed to the CAN-visible consequence
  modelled here) operates below the CAN layer entirely on signal timing,
  and critically is not stopped by rolling codes/freshness counters the
  way replay is - defending against it needs distance-bounding protocols,
  which are out of scope here.
- Timing is wall-clock (`time.sleep`/`threading`), not a deterministic
  discrete-event simulation, so exact message counts vary slightly run to
  run under OS scheduling jitter (repeats in the sweeps exist to average
  this out).
- The dashboard's engine, IDS, and DoIP gateway are separate, simplified
  reimplementations from `src/carnet`'s - a deliberate trade-off (the
  dashboard needs a controllable virtual clock the wall-clock-threaded
  `src/carnet` design doesn't support) but a maintenance risk: a fix to one
  side is not automatically reflected in the other.
- Full CAN-FD/LIN/FlexRay/Automotive-Ethernet, hardware-in-the-loop
  testing, and formal ISO/SAE 21434 / UNECE R155 compliance artefacts were
  considered and deliberately left out of scope - see the dissertation's
  Recommendations for Further Work.
