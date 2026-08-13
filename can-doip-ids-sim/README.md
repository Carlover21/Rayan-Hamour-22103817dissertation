# CAN/DoIP In-Vehicle Network Simulation with Rule-Based IDS

Author: Rayan Hamour (22103817)

Software simulation supporting the dissertation *"Detecting Cybersecurity
Attacks in In-Vehicle Networks Using CAN and DoIP Simulation"*. It models a
small in-vehicle CAN bus with several virtual ECUs, a conceptual DoIP
gateway representing the IP-connected diagnostic attack surface, a
rule-based intrusion detection system, and an evaluation harness that
scores detection rate and false positives.

No real vehicle hardware or SocketCAN is used. CAN is simulated via
python-can's virtual interface. DoIP has two models. `doip.gateway` is a
mocked in-process object (per the proposal's original scope: conceptual,
not full ISO 13400), used by the main evaluation harness because it's
fast. `doip.socket_gateway` is a real TCP-socket implementation of a
wire-format subset of ISO 13400-2 (`protocol.py`), added later as a more
accurate alternative and demonstrated in its own tests rather than wired
into every sweep.

Everything in this file describes `src/carnet`, the package the evaluation
chapter's numbers come from. `dashboard/` is a separate, simplified,
tick-based engine built purely for live visual demonstration (see its own
docstrings). It is not evaluation evidence and does not share code with
`src/carnet`.

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
    message.py         DoIPMessage / DoIPPayloadType (in-process model)
    gateway.py          DoIPGateway - routing activation + CAN forwarding, mocked
    protocol.py           wire-format encode/decode for a real-socket DoIP subset
    socket_gateway.py       SocketDoIPGateway + DoIPSocketClient - real TCP sockets
  security/
    secoc.py           simplified SecOC: per-ID derived keys, truncated HMAC + freshness
                        counter, scales to CAN-FD frame sizes via frame_len
  attacks/
    flood.py                    flooding / DoS
    spoof.py                    identifier spoofing
    doip_injection.py           unauthorized/abused CAN injection via DoIP (in-process)
    socket_doip_injection.py      same, over the real-socket DoIP gateway
    busoff.py                    bus-off / transmit-error-counter attack
    infotainment_pivot.py        attacker entry via a compromised infotainment unit, not DoIP
    key_fob_relay.py              single-shot relayed-unlock-command attack
    mimicry.py                     bus-timing-aware evasion against the rule-based IDS
    adversarial_ml.py               gray-box statistical evasion against the ML detector
    scenario.py                      AttackScenario + uniform run_scenario() dispatcher
  ids/
    detector.py       RuleBasedIDS - unknown ID / rate / timing / SecOC-auth / silence rules
    anomaly.py          AnomalyIDS - IsolationForest-based ML detector, for comparison
    sequence_dl.py        SequenceIDS - LSTM autoencoder over message-sequence windows
    alert.py                IDSAlert record
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

The LSTM sequence detector (`ids/sequence_dl.py`) needs PyTorch. It isn't
part of the core install above; that's deliberate, so the base package
stays lightweight. Install the CPU-only wheel, which is much smaller and
faster than the CUDA-inclusive default:

```bash
venv\Scripts\pip install torch --index-url https://download.pytorch.org/whl/cpu
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

# Live browser dashboard (visual demo only - see the note above)
venv\Scripts\python -m dashboard.app
# then open http://127.0.0.1:5000/

# Unit tests: 47 in total, including socket DoIP, CAN-FD, the
# mimicry/adversarial evasion attacks, and the LSTM sequence detector.
# None of those four have a dedicated run_*.py script, so read their
# test files if you want to see them exercised end to end.
venv\Scripts\python -m pytest tests/ -v
```

## How the pieces fit together

1. **`TrafficGenerator`** starts one `VirtualECU` per entry in
   `config.ECU_PROFILE` that has a nominal period. Each one sends its
   arbitration ID on the shared virtual CAN bus with realistic jitter.
   This is the "normal baseline" from the proposal. If a `SecOCContext` is
   supplied, every frame is authenticated (truncated HMAC + rolling
   counter) before it goes on the bus.
2. **`DoIPGateway`** models the IP-reachable diagnostic entry point. A
   tester must first perform routing activation, after which diagnostic
   messages are forwarded onto the CAN bus as a real frame (ID `0x7E0`).
   Unauthorized attempts (no activation) are rejected and logged. That's
   itself a security control, separate from the CAN-side IDS. The gateway
   never holds any per-ID SecOC key, so anything it forwards fails
   authentication when SecOC is enabled, even if the attacker completed
   routing activation.
3. **Attacks** (`attacks/`) run alongside normal traffic. Beyond the
   original flood/spoof/DoIP-injection scope: **bus-off** exploits CAN's
   own transmit-error-counter state machine to silence a victim ECU
   entirely (Cho & Shin, CCS 2016). **Infotainment-pivot** models an
   attacker who reaches the bus via a compromised head unit rather than
   DoIP, so the DoIP authorization gate never applies. **Key-fob relay**
   models the CAN-visible effect of a passive-keyless-entry relay attack
   as a single low-frequency event, deliberately testing whether a
   rate/pattern-based IDS can catch a lone malicious message.
4. **`RuleBasedIDS`** listens to every frame and applies five independent,
   config-driven rules: unknown arbitration ID, rate threshold, timing
   deviation, SecOC authentication failure (only when SecOC is enabled),
   and silence. Silence covers a periodic ID that's gone quiet far longer
   than its nominal period; it's the complementary case to rate threshold,
   and it's how bus-off attacks get caught.
5. **`AnomalyIDS`** is an alternative, ML-based detector: one scikit-learn
   `IsolationForest` per arbitration ID, trained on baseline traffic
   features. `eval.harness.run_trial` can run it in parallel with the
   rule-based detector against identical traffic, for a fair paired
   comparison. Each detector gets its own bus tap and dispatch thread, so
   the ML detector's slower per-message inference can't distort the
   rule-based detector's timing measurements.
6. **`eval.harness.run_trial`** wires all of the above together for one
   scenario. **`eval.sweep`** repeats it across attack intensities, so the
   two `run_evaluation*.py` scripts can report how detection rate and
   false positives change under varying attack pressure and configuration
   (SecOC on/off, rule-based vs ML).
7. **`dashboard/`** is a separate Flask app with its own tick-based
   simulation engine (a controllable virtual clock: pause, slow down,
   speed up, resume real-time, plus a history buffer for scrubbing and
   replaying past vehicle positions while paused). It has a small
   vehicle-dynamics model that turns decoded CAN signals into a car's
   on-screen position, and a live browser frontend (car/road view,
   instrument cluster with RPM/battery telemetry, scrolling CAN traffic
   graph). It does not share code with `src/carnet`, and it does **not**
   include CAN-FD, the real-socket DoIP gateway, the mimicry/adversarial
   attacks, or the LSTM detector. It stays a visualization and demo tool
   for the original core feature set, not part of the evaluation pipeline.
8. **`doip.socket_gateway.SocketDoIPGateway`** is a real TCP server:
   routing activation and diagnostic messages are actual bytes on a real
   socket (`doip.protocol`). Authorization is tracked per connection
   (reconnecting drops it) rather than by a persistent address set, which
   is a small accuracy improvement over the in-process `DoIPGateway`.
9. **CAN-FD**: `config.ECU_PROFILE` includes one FD-capable ID
   (`0x600 ADAS_Sensor_Fusion`, 32-byte frames). `SecOCContext.protect`
   and `verify` take a `frame_len` parameter, so authentication scales to
   frames up to 64 bytes rather than assuming classic CAN's 4-byte
   default.
10. **`attacks.mimicry`** and **`attacks.adversarial_ml`** are evasion
    attacks built to test the detectors against a deliberately careful
    adversary rather than a loud one. Mimicry taps the bus to time
    injections at the midpoint between legitimate transmissions, which
    evades the timing-deviation rule by construction. The ML-evasion
    attack passively learns the target ID's inter-arrival and
    payload-byte statistics, then injects frames that match them, evading
    IsolationForest's inlier region on a per-message basis.
11. **`ids.sequence_dl.SequenceIDS`** is a small PyTorch LSTM autoencoder
    per arbitration ID, trained on sliding windows of baseline traffic and
    scoring anomalies by reconstruction error. It was added specifically
    to test whether sequence and temporal context catches what the
    per-message detectors (rules, IsolationForest) miss.

## Key findings so far

- The original evaluation found a genuine rule-based-IDS blind spot. An
  attacker who completes DoIP routing activation like a legitimate
  tester, then abuses that access at a low rate (a handful of
  messages/sec), was **never** detected by the rate/timing rules alone,
  at any tested intensity. That's because the diagnostic ID has no
  periodic baseline to compare against, and its rate limit is tuned for
  much higher legitimate traffic.
- Enabling SecOC authentication closes that gap deterministically. The
  DoIP gateway never holds a per-ID key, so anything it forwards fails
  the `auth_invalid` check immediately, regardless of rate.
- The key-fob-relay attack (a single injected message, no flood) is
  largely not caught by either detector. The rule-based detector's timing
  rule only fires when the single event happens to land close enough in
  time to a legitimate message on the same ID (around 25% detection rate
  over 8 trials, consistent with a geometric argument based on where in
  the ID's roughly 100ms period the injection lands). The ML detector
  didn't catch it at all (0 out of 8) with the current feature set
  (inter-arrival time plus the first two payload bytes). Both false
  negatives are honest findings, not bugs: a well-timed single malicious
  message is a genuinely hard case for a threshold-based detector and for
  an unsupervised anomaly detector working from this feature set, and the
  comparison is a useful counter to any assumption that "ML-based"
  automatically means "more robust."
- Flooding, spoofing, and the bus-off attack were caught reliably (100%)
  by both detectors. The two approaches only really diverge on rare,
  single-shot events, not on sustained or high-rate attacks.
- The mimicry attack (timing injections at the midpoint between
  legitimate transmissions) measurably reduces rule-based alerts compared
  to a naive flood injecting the same overall volume. That confirms the
  timing-deviation and rate-threshold rules are evadable by a patient,
  bus-aware attacker, not just robust against loud ones.
- The gray-box ML-evasion attack has a lower per-message detection rate
  than a naive random injection, as intended. But because it has to send
  at close to the target ID's own cadence to blend in statistically, its
  raw alert count over a fixed duration can end up higher than a sparse
  naive flood's. Evasion success is a per-message property here, not
  necessarily a count-reduction one, which matters when reading any
  "detection rate" figure for this attack.
- The LSTM sequence detector trains in seconds on this toy dataset and
  did fire on windows containing a mimicry-attack message during ad-hoc
  testing. A rigorous rule-based-vs-ML-vs-sequence comparison, matching
  the rigor of the SecOC and flood/spoof/busoff comparisons above, hasn't
  been run as a full sweep yet. Treat single-run observations about it as
  illustrative, not as a validated result.

## Known limitations (for the dissertation's limitations section)

- DoIP is a conceptual, in-process model by default (no real UDP/TCP
  sockets, no full ISO 13400 payload structure), which is how the
  proposal explicitly scoped it.
- SecOC here is a simplified illustration (truncated HMAC and a rolling
  counter, one master key deriving per-ID keys), not a spec-accurate
  AUTOSAR SecOC implementation.
- The bus-off attack models the outcome of winning arbitration or forcing
  errors against a victim (an incrementing error counter crossing a
  threshold), not real CAN bit-level arbitration or error-frame physics.
  The underlying virtual bus has no electrical layer to model that on.
- A true RF relay attack, as opposed to the CAN-visible consequence
  modelled here, operates below the CAN layer entirely on signal timing.
  Critically, it is not stopped by rolling codes or freshness counters
  the way replay is; defending against it needs distance-bounding
  protocols, which are out of scope here.
- Timing is wall-clock (`time.sleep`/`threading`), not a deterministic
  discrete-event simulation, so exact message counts vary slightly from
  run to run under OS scheduling jitter. The repeats in the sweeps exist
  to average this out.
- The dashboard's engine, IDS, and DoIP gateway are separate, simplified
  reimplementations of `src/carnet`'s equivalents. That's a deliberate
  trade-off, since the dashboard needs a controllable virtual clock that
  the wall-clock-threaded `src/carnet` design doesn't support, but it's
  also a maintenance risk: a fix to one side isn't automatically
  reflected in the other.
- CAN-FD support is one illustrative FD-capable ID with variable-length
  SecOC, not a full CAN-FD implementation (no bit-rate switching, no
  distinct FD arbitration/CRC rules).
- `SocketDoIPGateway` implements a real TCP handshake and message
  exchange, but still only two payload types, and no UDP vehicle
  discovery, TLS, or multi-ECU logical addressing. It's a meaningful
  subset, not the full ISO 13400-2 stack.
- The LSTM sequence detector is trained per-run on whatever baseline
  traffic that run happens to generate: seconds of data, a few dozen
  windows. That's nowhere near the scale of data a real sequence model
  would see in production. Its role here is to test the mechanism (does
  sequence context catch what per-message models miss), not to claim
  production-grade accuracy.
- LIN, FlexRay, Automotive Ethernet, hardware-in-the-loop testing, and
  formal ISO/SAE 21434 / UNECE R155 compliance artefacts remain out of
  scope. See the dissertation's Recommendations for Further Work.
