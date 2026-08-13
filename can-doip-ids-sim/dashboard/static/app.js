// Author: Rayan Hamour (22103817)
const LANES = [
  { id: 0x300, name: "0x300 STEERING", color: "#4f8fd1" },
  { id: 0x100, name: "0x100 SPEED", color: "#4f9d69" },
  { id: 0x200, name: "0x200 BRAKE", color: "#c1453f" },
  { id: 0x400, name: "0x400 BODY", color: "#9a7fd6" },
  { id: 0x500, name: "0x500 BATTERY", color: "#c98a3a" },
  { id: 0x7e0, name: "0x7E0 DIAG", color: "#b8bec6" },
];
const LANE_INDEX = new Map(LANES.map((l, i) => [l.id, i]));
const KNOWN_ID_SET = new Set(LANES.map((l) => l.id));
const TRAFFIC_WINDOW_S = 6.0;
const SOURCE_COLOR = { ecu: "#5b6572", attack: "#c1453f", doip: "#c98a3a" };
const UNKNOWN_ID_COLOR = "#7a4fb0";

const POLL_MS = 90;

let sinceMsg = 0, sinceAlert = 0, sinceDoip = 0;
let messageBuf = [];
let alertBuf = [];
let latestState = null;

// client-side clock prediction, so rendering is smooth between 90ms polls
let predictedVT = 0;
let lastSyncPerf = performance.now();
let lastKnownSpeed = 1;
let lastKnownPaused = false;

// vehicle interpolation between the last two polled snapshots
let prevVehicle = null, currVehicle = null;
let prevVehicleVT = 0, currVehicleVT = 0;

// history scrub/replay (only meaningful while paused)
let scrubbedVehicle = null;
let scrubActive = false;
let pausedAtVT = 0;

let recentMsgTimes = [];

const $ = (sel) => document.querySelector(sel);
const roadCanvas = $("#road-canvas");
const trafficCanvas = $("#traffic-canvas");
const gaugeCanvas = $("#gauge-canvas");

// instrument cluster reactive state
let glitchUntil = 0;   // performance.now() timestamp - cluster "self-test" sweep while a
                        // DoIP diagnostic message is actually reaching the CAN bus
let deniedFlashUntil = 0; // brief red flash when the gateway rejects an unauthorized attempt
const GLITCH_MS = 420;
const DENIED_FLASH_MS = 320;

function currentPredictedVT() {
  if (lastKnownPaused) return predictedVT;
  const elapsed = (performance.now() - lastSyncPerf) / 1000;
  return predictedVT + elapsed * lastKnownSpeed;
}

async function poll() {
  try {
    const url = `/api/state?since_msg=${sinceMsg}&since_alert=${sinceAlert}&since_doip=${sinceDoip}`;
    const res = await fetch(url);
    const state = await res.json();
    latestState = state;

    predictedVT = state.virtual_time;
    lastSyncPerf = performance.now();
    lastKnownSpeed = state.speed;
    lastKnownPaused = state.paused;

    prevVehicle = currVehicle || state.vehicle;
    prevVehicleVT = currVehicleVT || state.virtual_time;
    currVehicle = state.vehicle;
    currVehicleVT = state.virtual_time;

    const now = performance.now();
    for (const m of state.new_messages) {
      messageBuf.push(m);
      recentMsgTimes.push(now);
    }
    for (const a of state.new_alerts) {
      alertBuf.push(a);
      prependAlertRow(a);
    }
    for (const e of state.new_doip_events) {
      prependDoipRow(e);
      if (e.kind === "forwarded_to_can") glitchUntil = performance.now() + GLITCH_MS;
      if (e.kind === "unauthorized_diagnostic_attempt") deniedFlashUntil = performance.now() + DENIED_FLASH_MS;
    }

    sinceMsg = state.last_msg_seq;
    sinceAlert = state.last_alert_seq;
    sinceDoip = state.last_doip_seq;

    const cutoff = state.virtual_time - TRAFFIC_WINDOW_S - 1;
    messageBuf = messageBuf.filter((m) => m.timestamp >= cutoff);
    alertBuf = alertBuf.filter((a) => a.timestamp >= cutoff);
    recentMsgTimes = recentMsgTimes.filter((t) => now - t < 1000);

    updateHeader(state);
    updateReadouts(state);
    updateWarningLights(state);
    updateScrubVisibility(state);
    $("#alert-count-badge").textContent = state.total_alerts;
    $("#msg-rate-meta").textContent = `${recentMsgTimes.length} msg/s`;
    $("#pos-meta").textContent = `x=${state.vehicle.x_m.toFixed(1)}m`;
  } catch (err) {
    console.error("poll failed", err);
  }
  setTimeout(poll, POLL_MS);
}

function updateHeader(state) {
  $("#clock").textContent = `t=${state.virtual_time.toFixed(3)}s  x${state.speed}${state.paused ? "  PAUSED" : ""}`;
  const banner = $("#status-banner");
  if (state.vehicle.off_road) {
    banner.textContent = "OFF ROAD - IMPACT";
    banner.className = "crash";
  } else if (state.active_attack) {
    banner.textContent = `ATTACK: ${state.active_attack.kind.toUpperCase()} -> ${state.active_attack.target}`;
    banner.className = "attack";
  } else {
    banner.textContent = "NORMAL";
    banner.className = "";
  }
  $("#active-attack-label").textContent = state.active_attack
    ? `${state.active_attack.kind} / ${state.active_attack.target} @ ${state.active_attack.rate_hz}/s`
    : "none";
}

function updateReadouts(state) {
  $("#speed-val").textContent = `${state.signals.speed_kmh.toFixed(0)} km/h`;
  $("#steering-val").textContent = `${state.signals.steering_deg.toFixed(1)}°`;
  const brakeEl = $("#brake-val");
  brakeEl.textContent = state.signals.brake ? "APPLIED" : "RELEASED";
  brakeEl.className = "value " + (state.signals.brake ? "on" : "off");
  $("#rpm-val").textContent = `${Math.round(state.signals.rpm)}`;
  $("#battery-val").textContent = `${state.signals.battery_v.toFixed(1)}V`;
}

function updateScrubVisibility(state) {
  const field = $("#scrub-field");
  const slider = $("#scrub-slider");
  if (state.paused) {
    if (field.style.display === "none") {
      pausedAtVT = state.virtual_time;
      slider.value = 1000;
      $("#scrub-out").textContent = "live";
    }
    field.style.display = "block";
  } else {
    field.style.display = "none";
    scrubActive = false;
    scrubbedVehicle = null;
  }
}

function updateWarningLights(state) {
  const now = performance.now();
  const diagSession = state.active_attack && state.active_attack.kind === "doip" && state.active_attack.authorized;
  const diagDenied = now < deniedFlashUntil;
  const glitching = now < glitchUntil;

  const recentAlert = alertBuf.some((a) => state.virtual_time - a.timestamp < 1.0);
  setLight("#warn-check-engine", recentAlert ? "lit-amber" : null);
  setLight("#warn-brake", state.signals.brake ? "lit-red" : null);
  setLight("#warn-airbag", state.vehicle.off_road ? "lit-red flash" : null);
  setLight("#warn-diag", diagDenied ? "lit-red flash" : diagSession || glitching ? "lit-amber" : null);

  $("#diag-session-meta").textContent = diagDenied
    ? "SESSION: denied"
    : diagSession
    ? "SESSION: active (authorized)"
    : "SESSION: closed";

  document.getElementById("cluster").classList.toggle("glitch", glitching);
}

function setLight(sel, classes) {
  const el = $(sel);
  el.className = "warn-light" + (classes ? " " + classes : "");
}

function prependAlertRow(a) {
  const feed = $("#alert-feed");
  const row = document.createElement("div");
  row.className = "alert-row " + a.rule;
  row.textContent = `${a.timestamp.toFixed(2)}s ${a.arbitration_id_hex} ${a.rule} ${a.detail}`;
  feed.appendChild(row);
  while (feed.children.length > 150) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

function prependDoipRow(e) {
  const feed = $("#doip-feed");
  const row = document.createElement("div");
  row.className = "doip-row " + e.kind;
  let extra = "";
  if (e.can_id !== undefined) extra = ` -> can:0x${e.can_id.toString(16).toUpperCase()}`;
  row.textContent = `${e.timestamp.toFixed(2)}s ${e.kind} src:0x${e.source.toString(16).toUpperCase()}${extra}`;
  feed.appendChild(row);
  while (feed.children.length > 80) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

function lerp(a, b, t) { return a + (b - a) * t; }
function lerpAngle(a, b, t) {
  let d = b - a;
  while (d > 180) d -= 360;
  while (d < -180) d += 360;
  return a + d * t;
}

function interpolatedVehicle() {
  if (scrubActive && scrubbedVehicle) return scrubbedVehicle;
  if (!currVehicle) return null;
  if (!prevVehicle || currVehicleVT <= prevVehicleVT) return currVehicle;
  const vt = currentPredictedVT();
  let t = (vt - prevVehicleVT) / (currVehicleVT - prevVehicleVT);
  t = Math.max(0, Math.min(1.6, t)); // allow slight extrapolation past the last poll
  return {
    x_m: lerp(prevVehicle.x_m, currVehicle.x_m, t),
    y_m: lerp(prevVehicle.y_m, currVehicle.y_m, t),
    heading_deg: lerpAngle(prevVehicle.heading_deg, currVehicle.heading_deg, t),
    speed_kmh: lerp(prevVehicle.speed_kmh, currVehicle.speed_kmh, t),
    off_road: currVehicle.off_road,
    road_half_width_m: currVehicle.road_half_width_m,
  };
}

// ---- Road / car rendering -------------------------------------------------
function drawRoad() {
  const ctx = roadCanvas.getContext("2d");
  const w = roadCanvas.width, h = roadCanvas.height;
  const veh = interpolatedVehicle();
  ctx.clearRect(0, 0, w, h);
  if (!veh) return;

  const roadHalfWidthM = veh.road_half_width_m;
  const pxPerMeter = (h * 0.4) / roadHalfWidthM;
  const centerY = h / 2;
  const roadTop = centerY - roadHalfWidthM * pxPerMeter;
  const roadBottom = centerY + roadHalfWidthM * pxPerMeter;

  ctx.fillStyle = veh.off_road ? "#1d0f0e" : "#0e1013";
  ctx.fillRect(0, 0, w, h);

  // shoulders (hazard-striped)
  ctx.save();
  ctx.beginPath();
  ctx.rect(0, 0, w, roadTop);
  ctx.rect(0, roadBottom, w, h - roadBottom);
  ctx.clip();
  ctx.strokeStyle = "rgba(201,138,58,0.25)";
  ctx.lineWidth = 6;
  for (let x = -h; x < w + h; x += 22) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x + h, h);
    ctx.stroke();
  }
  ctx.restore();

  ctx.fillStyle = "#181c22";
  ctx.fillRect(0, roadTop, w, roadBottom - roadTop);

  ctx.strokeStyle = veh.off_road ? "#c1453f" : "#33383f";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, roadTop); ctx.lineTo(w, roadTop);
  ctx.moveTo(0, roadBottom); ctx.lineTo(w, roadBottom);
  ctx.stroke();

  const dashPeriod = 36;
  const scrollPx = (veh.x_m * pxPerMeter * 0.55) % dashPeriod;
  ctx.strokeStyle = "#2b3138";
  ctx.lineWidth = 2;
  ctx.setLineDash([16, 12]);
  ctx.beginPath();
  ctx.moveTo(-scrollPx, centerY);
  ctx.lineTo(w, centerY);
  ctx.stroke();
  ctx.setLineDash([]);

  // distance ticks along bottom edge of the road
  ctx.strokeStyle = "#242a31";
  ctx.font = "9px " + getComputedStyle(document.body).getPropertyValue("--mono");
  ctx.fillStyle = "#4a5158";
  const tickPeriod = 90;
  const tickScroll = (veh.x_m * pxPerMeter * 0.55) % tickPeriod;
  for (let x = -tickScroll; x < w; x += tickPeriod) {
    ctx.beginPath();
    ctx.moveTo(x, roadBottom);
    ctx.lineTo(x, roadBottom + 6);
    ctx.stroke();
  }

  drawCar(ctx, w * 0.26, centerY + veh.y_m * pxPerMeter, veh.heading_deg, veh.off_road);

  ctx.fillStyle = "#4a5158";
  ctx.font = "11px " + getComputedStyle(document.body).getPropertyValue("--mono");
  ctx.fillText(`lateral offset ${veh.y_m.toFixed(2)}m  (road ±${roadHalfWidthM}m)  heading ${veh.heading_deg.toFixed(1)}°`, 10, h - 8);
}

function drawCar(ctx, cx, cy, headingDeg, offRoad) {
  ctx.save();
  ctx.translate(cx, cy);
  ctx.rotate((headingDeg * Math.PI) / 180);

  const bodyColor = offRoad ? "#c1453f" : "#c7ccd2";
  const glassColor = "#0e1013";

  // wheels
  ctx.fillStyle = "#05070a";
  ctx.fillRect(-16, -15, 8, 6);
  ctx.fillRect(-16, 9, 8, 6);
  ctx.fillRect(10, -15, 8, 6);
  ctx.fillRect(10, 9, 8, 6);

  // body (side-view silhouette: low hood, cabin bump, trunk)
  ctx.fillStyle = bodyColor;
  ctx.beginPath();
  ctx.moveTo(-30, 4);
  ctx.lineTo(-26, -4);
  ctx.lineTo(-14, -4);
  ctx.lineTo(-9, -13);
  ctx.lineTo(11, -13);
  ctx.lineTo(17, -4);
  ctx.lineTo(30, -4);
  ctx.lineTo(32, 6);
  ctx.lineTo(-30, 6);
  ctx.closePath();
  ctx.fill();

  // cabin glass
  ctx.fillStyle = glassColor;
  ctx.beginPath();
  ctx.moveTo(-11, -4);
  ctx.lineTo(-7, -11);
  ctx.lineTo(9, -11);
  ctx.lineTo(14, -4);
  ctx.closePath();
  ctx.fill();

  ctx.fillStyle = "#e8c14a";
  ctx.fillRect(29, -2, 3, 3);
  ctx.fillStyle = "#8a1410";
  ctx.fillRect(-31, -2, 3, 3);

  ctx.restore();
}

// ---- Instrument cluster gauge ------------------------------------------------
const GAUGE_MAX_KMH = 220;

function drawGauge() {
  const ctx = gaugeCanvas.getContext("2d");
  const w = gaugeCanvas.width, h = gaugeCanvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#0e1013";
  ctx.fillRect(0, 0, w, h);

  const veh = interpolatedVehicle();
  let speed = veh ? veh.speed_kmh : 0;

  const now = performance.now();
  const glitching = now < glitchUntil;
  if (glitching) {
    const progress = 1 - (glitchUntil - now) / GLITCH_MS;
    const envelope = Math.sin(Math.min(progress, 1) * Math.PI);
    speed = speed + envelope * (GAUGE_MAX_KMH + 15 - speed);
  }

  const cx = w / 2, cy = h - 12, radius = Math.min(w / 2 - 14, h - 30);
  const angleFor = (kmh) => Math.PI - (Math.max(0, Math.min(kmh, GAUGE_MAX_KMH * 1.1)) / GAUGE_MAX_KMH) * Math.PI;

  ctx.strokeStyle = "#242a31";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(cx, cy, radius, Math.PI, 0, false);
  ctx.stroke();

  ctx.strokeStyle = "#5a2622";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.arc(cx, cy, radius, angleFor(GAUGE_MAX_KMH * 0.82), 0, false);
  ctx.stroke();

  ctx.fillStyle = "#525a63";
  ctx.font = "9px " + getComputedStyle(document.body).getPropertyValue("--mono");
  for (let v = 0; v <= GAUGE_MAX_KMH; v += 20) {
    const a = angleFor(v);
    const x1 = cx + Math.cos(a) * radius, y1 = cy - Math.sin(a) * radius;
    const x2 = cx + Math.cos(a) * (radius - 7), y2 = cy - Math.sin(a) * (radius - 7);
    ctx.strokeStyle = "#3a4048";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x1, y1); ctx.lineTo(x2, y2);
    ctx.stroke();
    if (v % 40 === 0) {
      const lx = cx + Math.cos(a) * (radius - 18), ly = cy - Math.sin(a) * (radius - 18);
      ctx.fillText(String(v), lx - 7, ly + 3);
    }
  }

  const needleAngle = angleFor(speed);
  ctx.strokeStyle = glitching ? "#ff8f88" : "#e8c14a";
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(cx + Math.cos(needleAngle) * (radius - 12), cy - Math.sin(needleAngle) * (radius - 12));
  ctx.stroke();
  ctx.fillStyle = "#8b929b";
  ctx.beginPath();
  ctx.arc(cx, cy, 3.5, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = glitching ? "#ff8f88" : "#d7dce2";
  ctx.font = "bold 15px " + getComputedStyle(document.body).getPropertyValue("--mono");
  ctx.textAlign = "center";
  ctx.fillText(`${Math.round(speed)}`, cx, cy - 22);
  ctx.font = "9px " + getComputedStyle(document.body).getPropertyValue("--mono");
  ctx.fillStyle = "#525a63";
  ctx.fillText(glitching ? "SELF TEST" : "KM/H", cx, cy - 10);
  ctx.textAlign = "left";
}

// ---- Traffic graph ---------------------------------------------------------
function drawTraffic() {
  const ctx = trafficCanvas.getContext("2d");
  const w = trafficCanvas.width, h = trafficCanvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = "#0e1013";
  ctx.fillRect(0, 0, w, h);
  if (!latestState) return;

  const now = currentPredictedVT();
  const unknownLaneY = h - 12;
  const laneH = (h - 16) / LANES.length;

  ctx.font = "10px " + getComputedStyle(document.body).getPropertyValue("--mono");
  LANES.forEach((lane, i) => {
    const y = i * laneH;
    ctx.strokeStyle = "#1a1e24";
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
    ctx.fillStyle = "#525a63";
    ctx.fillText(lane.name, 6, y + 12);
  });

  const xFor = (t) => w - ((now - t) / TRAFFIC_WINDOW_S) * w;

  for (const m of messageBuf) {
    const x = xFor(m.timestamp);
    if (x < 0 || x > w) continue;
    const laneIdx = LANE_INDEX.get(m.arbitration_id);
    const y = laneIdx === undefined ? unknownLaneY : laneIdx * laneH + laneH / 2;
    ctx.fillStyle = laneIdx === undefined ? UNKNOWN_ID_COLOR : SOURCE_COLOR[m.source] || "#5b6572";
    ctx.fillRect(x - 1, y - 1, 2, 2);
  }

  for (const a of alertBuf) {
    const x = xFor(a.timestamp);
    if (x < 0 || x > w) continue;
    const laneIdx = LANE_INDEX.get(a.arbitration_id);
    const y = laneIdx === undefined ? unknownLaneY : laneIdx * laneH + laneH / 2;
    ctx.strokeStyle = "#e8c14a";
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.moveTo(x - 3, y - 3); ctx.lineTo(x + 3, y + 3);
    ctx.moveTo(x + 3, y - 3); ctx.lineTo(x - 3, y + 3);
    ctx.stroke();
  }

  ctx.strokeStyle = "#1a1e24";
  ctx.beginPath();
  ctx.moveTo(0, h - 16);
  ctx.lineTo(w, h - 16);
  ctx.stroke();
  ctx.fillStyle = "#525a63";
  ctx.fillText("UNKNOWN ID", 6, h - 4);
}

function renderLoop() {
  drawGauge();
  drawRoad();
  drawTraffic();
  requestAnimationFrame(renderLoop);
}

// ---- Controls ---------------------------------------------------------------
async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

let paused = false;
$("#btn-pause").addEventListener("click", async () => {
  paused = !paused;
  await postJSON("/api/control/pause", { paused });
  $("#btn-pause").textContent = paused ? "Resume" : "Pause";
  $("#btn-pause").classList.toggle("active", paused);
});

$("#btn-resume-rt").addEventListener("click", async () => {
  await postJSON("/api/control/resume_realtime");
  paused = false;
  $("#btn-pause").textContent = "Pause";
  $("#btn-pause").classList.remove("active");
  document.querySelectorAll("#speed-buttons button").forEach((b) => b.classList.toggle("active", b.dataset.speed === "1"));
});

document.querySelectorAll("#speed-buttons button").forEach((btn) => {
  btn.addEventListener("click", async () => {
    await postJSON("/api/control/speed", { speed: parseFloat(btn.dataset.speed) });
    document.querySelectorAll("#speed-buttons button").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
  });
});

$("#btn-reset").addEventListener("click", async () => {
  await postJSON("/api/control/reset");
  messageBuf = [];
  alertBuf = [];
  recentMsgTimes = [];
  sinceMsg = 0;
  sinceAlert = 0;
  sinceDoip = 0;
  prevVehicle = null;
  currVehicle = null;
  glitchUntil = 0;
  deniedFlashUntil = 0;
  scrubActive = false;
  scrubbedVehicle = null;
  $("#alert-feed").innerHTML = "";
  $("#doip-feed").innerHTML = "";
});

const kindSelect = $("#attack-kind");
const authorizedField = $("#authorized-field");
const targetField = $("#target-field");
const magnitudeField = $("#magnitude-field");

function syncAttackForm() {
  const kind = kindSelect.value;
  authorizedField.style.display = kind === "doip" ? "block" : "none";
  targetField.style.display = kind === "fuzz" || kind === "bus_flood" ? "none" : "block";
  magnitudeField.style.display = kind === "spoof" || kind === "doip" ? "block" : "none";
}
kindSelect.addEventListener("change", syncAttackForm);
syncAttackForm();

const rateSlider = $("#attack-rate");
rateSlider.addEventListener("input", () => ($("#rate-out").textContent = rateSlider.value));

$("#btn-attack-start").addEventListener("click", async () => {
  await postJSON("/api/attack/start", {
    kind: kindSelect.value,
    target: $("#attack-target").value,
    rate_hz: parseFloat(rateSlider.value),
    magnitude: $("#attack-magnitude").value === "" ? null : parseFloat($("#attack-magnitude").value),
    authorized: $("#attack-authorized").checked,
  });
});

$("#btn-attack-stop").addEventListener("click", async () => {
  await postJSON("/api/attack/stop");
});

const scrubSlider = $("#scrub-slider");
scrubSlider.addEventListener("input", async () => {
  const frac = parseInt(scrubSlider.value, 10) / 1000;
  if (frac >= 0.999) {
    scrubActive = false;
    scrubbedVehicle = null;
    $("#scrub-out").textContent = "live";
    return;
  }
  const targetT = frac * pausedAtVT;
  $("#scrub-out").textContent = `${targetT.toFixed(1)}s`;
  try {
    const res = await fetch(`/api/scrub?t=${targetT}`);
    const data = await res.json();
    if (data.ok) {
      scrubbedVehicle = data.vehicle;
      scrubActive = true;
    }
  } catch (err) {
    console.error("scrub failed", err);
  }
});

poll();
renderLoop();
