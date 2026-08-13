# Author: Rayan Hamour (22103817)
"""
Flask app serving the live CAN/DoIP attack dashboard: a polling JSON API
backed by the tick-based SimEngine, plus the static frontend (car/road
canvas, live CAN traffic graph, IDS alert feed, time and attack controls).

Run from the project root with:
    venv\\Scripts\\python.exe -m dashboard.app
then open http://127.0.0.1:5000/
"""

from __future__ import annotations

from flask import Flask, jsonify, request, send_from_directory

from dashboard.engine import SimEngine

app = Flask(__name__, static_folder="static", static_url_path="")
engine = SimEngine()


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/state")
def api_state():
    since_msg = request.args.get("since_msg", default=0, type=int)
    since_alert = request.args.get("since_alert", default=0, type=int)
    since_doip = request.args.get("since_doip", default=0, type=int)
    return jsonify(engine.get_state(since_msg, since_alert, since_doip))


@app.post("/api/control/pause")
def api_pause():
    payload = request.get_json(silent=True) or {}
    engine.set_paused(bool(payload.get("paused", True)))
    return jsonify({"ok": True, "paused": engine.paused})


@app.post("/api/control/speed")
def api_speed():
    payload = request.get_json(silent=True) or {}
    try:
        value = float(payload.get("speed", 1.0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "speed must be a number"}), 400
    engine.set_speed(value)
    return jsonify({"ok": True, "speed": engine.speed})


@app.post("/api/control/resume_realtime")
def api_resume_realtime():
    engine.resume_realtime()
    return jsonify({"ok": True, "speed": engine.speed, "paused": engine.paused})


@app.post("/api/control/reset")
def api_reset():
    engine.reset_scenario()
    return jsonify({"ok": True})


@app.get("/api/scrub")
def api_scrub():
    t = request.args.get("t", type=float)
    if t is None:
        return jsonify({"ok": False, "error": "t (virtual time) is required"}), 400
    vehicle = engine.get_vehicle_at(t)
    if vehicle is None:
        return jsonify({"ok": False, "error": "no history recorded yet"}), 404
    return jsonify({"ok": True, "t": t, "vehicle": vehicle})


@app.post("/api/attack/start")
def api_attack_start():
    payload = request.get_json(silent=True) or {}
    kind = payload.get("kind")
    target = payload.get("target")
    if kind not in {"flood", "spoof", "doip", "fuzz", "replay", "bus_flood"}:
        return jsonify({"ok": False, "error": "kind must be flood|spoof|doip|fuzz|replay|bus_flood"}), 400
    if target not in {"steering", "speed", "brake", "diagnostic"}:
        return jsonify({"ok": False, "error": "target must be steering|speed|brake|diagnostic"}), 400
    rate_hz = float(payload.get("rate_hz", 20))
    magnitude = payload.get("magnitude")
    magnitude = float(magnitude) if magnitude is not None else None
    authorized = bool(payload.get("authorized", True))
    engine.start_attack(kind, target, rate_hz, magnitude, authorized)
    return jsonify({"ok": True})


@app.post("/api/attack/stop")
def api_attack_stop():
    engine.stop_attack()
    return jsonify({"ok": True})


if __name__ == "__main__":
    engine.start()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False, threaded=True)
