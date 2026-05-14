"""
Wrong Way Vehicle Detection System (WWVDS) - SunGuide HTTP Protocol Simulator

Implements the FDOT WWVDS SunGuide HTTP Protocol (Rev 3.0, March 2026):

  WWVDS Device endpoints (this server acts as the device):
    GET  /v1/status?DeviceId={id}   -> XML device status

  SunGuide receiver endpoints (this server acts as SunGuide):
    POST /v1/alert                  -> receive alert XML from device
    POST /v1/update                 -> receive image-update XML from device

  Web management API:
    GET/POST        /api/devices
    GET/PUT/DELETE  /api/devices/<id>
    POST            /api/devices/<id>/alert   - simulate device generating an alert
    POST            /api/devices/<id>/update  - simulate device sending an image update
    GET             /api/alerts
    DELETE          /api/alerts
    GET             /api/events               - SSE stream
    GET/POST        /api/settings             - SunGuide target URL config
"""

from flask import Flask, request, jsonify, render_template, Response, stream_with_context
import xml.etree.ElementTree as ET
from datetime import datetime
import uuid
import json
import threading
import queue
import random
import requests as http_requests
import os

app = Flask(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────

DEVICE_STATUSES = ["Active", "Error", "Out of Service"]
DIRECTIONS = ["Northbound", "Eastbound", "Southbound", "Westbound", "Innerloop", "Outerloop"]
def snapshot_urls(snapshot_set: int, num_snapshots: int) -> list[str]:
    base = settings.get("snapshotBaseUrl", "").rstrip("/")
    return [
        f"{base}/{snapshot_set:03d}/snapshot_{i:03d}.jpg"
        for i in range(num_snapshots)
    ]

# ─── Persistence ─────────────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")


def save_config() -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"devices": list(devices.values()), "settings": settings}, f, indent=2)


def load_config() -> None:
    if not os.path.exists(CONFIG_FILE):
        return
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            data = json.load(f)
        for dev in data.get("devices", []):
            devices[dev["deviceId"]] = dev
        settings.update(data.get("settings", {}))
        print(f"Loaded {len(devices)} device(s) from {CONFIG_FILE}")
    except Exception as exc:
        print(f"Warning: could not load {CONFIG_FILE}: {exc}")


# ─── In-memory state ──────────────────────────────────────────────────────────

devices: dict[str, dict] = {}
event_log: list[dict] = []
sse_queues: list[queue.Queue] = []
settings: dict = {
    "sunguideUrl": "",
    "forwardToSunguide": False,
    "snapshotBaseUrl": "",
}

devices_lock = threading.Lock()
log_lock = threading.Lock()
queues_lock = threading.Lock()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def iso_now() -> str:
    now = datetime.now().astimezone()
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.0000000")
    raw_offset = now.strftime("%z")          # e.g. -0400
    offset = raw_offset[:3] + ":" + raw_offset[3:]  # -> -04:00
    return ts + offset


def broadcast(data: dict):
    payload = json.dumps(data)
    with queues_lock:
        dead = [q for q in sse_queues if q.full()]
        for q in dead:
            sse_queues.remove(q)
        for q in sse_queues:
            try:
                q.put_nowait(payload)
            except queue.Full:
                pass


def xml_response(body: str, status: int = 200) -> Response:
    return Response(body, status=status, mimetype="application/xml")


def pretty_xml(xml_str: str) -> str:
    try:
        root = ET.fromstring(xml_str)
        ET.indent(root, space="  ")
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
    except Exception:
        return xml_str


# ─── XML builders ────────────────────────────────────────────────────────────

def build_status_xml(device: dict) -> str:
    root = ET.Element("status")
    ET.SubElement(root, "deviceId").text = device["deviceId"]
    ET.SubElement(root, "deviceStatus").text = device["deviceStatus"]
    ET.SubElement(root, "deviceTimestamp").text = iso_now()
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def build_alert_xml(data: dict) -> str:
    root = ET.Element("alert")
    ET.SubElement(root, "alertId").text = data["alertId"]
    ET.SubElement(root, "deviceId").text = data["deviceId"]
    ET.SubElement(root, "alertTimestamp").text = data["alertTimestamp"]
    if data.get("images"):
        il = ET.SubElement(root, "imageList")
        for url in data["images"]:
            ET.SubElement(il, "imageLocation").text = url
    if data.get("roadway"):
        ET.SubElement(root, "roadway").text = data["roadway"]
    if data.get("direction"):
        ET.SubElement(root, "direction").text = data["direction"]
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def build_update_xml(data: dict) -> str:
    root = ET.Element("update")
    ET.SubElement(root, "alertId").text = data["alertId"]
    ET.SubElement(root, "deviceId").text = data["deviceId"]
    ET.SubElement(root, "updateTimestamp").text = data["updateTimestamp"]
    il = ET.SubElement(root, "imageList")
    for url in data["images"]:
        ET.SubElement(il, "imageLocation").text = url
    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def parse_alert_xml(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    return {
        "type": "alert",
        "alertId": root.findtext("alertId", ""),
        "deviceId": root.findtext("deviceId", ""),
        "alertTimestamp": root.findtext("alertTimestamp", ""),
        "images": [e.text for e in root.findall("./imageList/imageLocation")],
        "roadway": root.findtext("roadway", ""),
        "direction": root.findtext("direction", ""),
        "receivedAt": iso_now(),
        "xmlPayload": pretty_xml(xml_str),
        "source": "external",
    }


def parse_update_xml(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    return {
        "type": "update",
        "alertId": root.findtext("alertId", ""),
        "deviceId": root.findtext("deviceId", ""),
        "updateTimestamp": root.findtext("updateTimestamp", ""),
        "images": [e.text for e in root.findall("./imageList/imageLocation")],
        "receivedAt": iso_now(),
        "xmlPayload": pretty_xml(xml_str),
        "source": "external",
    }


def store_and_broadcast(entry: dict):
    with log_lock:
        event_log.append(entry)
    broadcast(entry)


def maybe_forward_to_sunguide(endpoint: str, xml_str: str) -> dict | None:
    """POST xml to external SunGuide URL if configured. Returns response info or None."""
    url = settings.get("sunguideUrl", "").rstrip("/")
    if not settings.get("forwardToSunguide") or not url:
        return None
    target = f"{url}{endpoint}"
    try:
        resp = http_requests.post(
            target, data=xml_str.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
            timeout=5,
        )
        return {"url": target, "status": resp.status_code, "body": resp.text[:500]}
    except Exception as exc:
        return {"url": target, "error": str(exc)}


# ─── WWVDS Device Endpoints ───────────────────────────────────────────────────

@app.route("/v1/status")
def device_status():
    """SunGuide polls this to get device status."""
    device_id = request.args.get("DeviceId", "").strip()
    if not device_id:
        return xml_response("<error>Missing DeviceId parameter</error>", 400)
    with devices_lock:
        device = devices.get(device_id)
    if not device:
        return xml_response(f"<error>Device '{device_id}' not found</error>", 404)
    return xml_response(build_status_xml(device))


# ─── SunGuide Receiver Endpoints ──────────────────────────────────────────────

@app.route("/v1/alert", methods=["POST"])
def receive_alert():
    """WWVDS device POSTs an alert to SunGuide."""
    xml_str = request.get_data(as_text=True).strip()
    if not xml_str:
        return xml_response("<error>Empty request body</error>", 400)
    try:
        entry = parse_alert_xml(xml_str)
        store_and_broadcast(entry)
        return xml_response("<response>OK</response>", 200)
    except ET.ParseError as exc:
        return xml_response(f"<error>Invalid XML: {exc}</error>", 400)


@app.route("/v1/update", methods=["POST"])
def receive_update():
    """WWVDS device POSTs an image update to SunGuide."""
    xml_str = request.get_data(as_text=True).strip()
    if not xml_str:
        return xml_response("<error>Empty request body</error>", 400)
    try:
        entry = parse_update_xml(xml_str)
        store_and_broadcast(entry)
        return xml_response("<response>OK</response>", 200)
    except ET.ParseError as exc:
        return xml_response(f"<error>Invalid XML: {exc}</error>", 400)


# ─── Device Management API ────────────────────────────────────────────────────

@app.route("/api/devices", methods=["GET"])
def api_list_devices():
    with devices_lock:
        return jsonify(list(devices.values()))


@app.route("/api/devices", methods=["POST"])
def api_add_device():
    data = request.get_json(force=True)
    did = (data.get("deviceId") or "").strip()
    if not did:
        return jsonify({"error": "deviceId is required"}), 400
    with devices_lock:
        if did in devices:
            return jsonify({"error": f"Device '{did}' already exists"}), 409
        snap_set = data.get("snapshotSet")
        dev = {
            "deviceId": did,
            "name": (data.get("name") or did).strip(),
            "deviceStatus": data.get("deviceStatus", "Active"),
            "roadway": (data.get("roadway") or "").strip(),
            "direction": (data.get("direction") or "").strip(),
            "ipAddress": (data.get("ipAddress") or "127.0.0.1").strip(),
            "snapshotSet": int(snap_set) if snap_set else None,
            "numSnapshots": int(data.get("numSnapshots") or 1) if snap_set else None,
        }
        devices[did] = dev
    save_config()
    return jsonify(dev), 201


@app.route("/api/devices/<did>", methods=["PUT"])
def api_update_device(did):
    data = request.get_json(force=True)
    with devices_lock:
        if did not in devices:
            return jsonify({"error": "Device not found"}), 404
        dev = devices[did]
        for key in ("name", "deviceStatus", "roadway", "direction", "ipAddress"):
            if key in data:
                dev[key] = (data[key] or "").strip() if key != "deviceStatus" else data[key]
        if "snapshotSet" in data:
            snap_set = data["snapshotSet"]
            dev["snapshotSet"] = int(snap_set) if snap_set else None
            dev["numSnapshots"] = int(data.get("numSnapshots") or 1) if snap_set else None
    save_config()
    return jsonify(dev)


@app.route("/api/devices/<did>", methods=["DELETE"])
def api_delete_device(did):
    with devices_lock:
        if did not in devices:
            return jsonify({"error": "Device not found"}), 404
        del devices[did]
    save_config()
    return "", 204


# ─── Alert / Update Generation API ───────────────────────────────────────────

@app.route("/api/devices/<did>/alert", methods=["POST"])
def api_generate_alert(did):
    """Simulate the WWVDS device generating and sending an alert."""
    with devices_lock:
        dev = devices.get(did)
    if not dev:
        return jsonify({"error": "Device not found"}), 404

    body = request.get_json(force=True) or {}
    alert_id = str(uuid.uuid4())
    ts = iso_now()

    if dev.get("snapshotSet"):
        images = snapshot_urls(dev["snapshotSet"], dev["numSnapshots"])
    else:
        num_images = int(body.get("numImages", random.randint(1, 3)))
        num_images = max(0, min(10, num_images))
        images = [f"http://{dev['ipAddress']}/images/{alert_id}/frame{i+1:02d}.jpg" for i in range(num_images)]

    roadway = (body.get("roadway") or dev.get("roadway") or "").strip()
    direction = (body.get("direction") or dev.get("direction") or "").strip()

    alert_data = {
        "alertId": alert_id,
        "deviceId": did,
        "alertTimestamp": ts,
        "images": images,
        "roadway": roadway,
        "direction": direction,
    }
    xml_str = build_alert_xml(alert_data)

    entry = {
        "type": "alert",
        **alert_data,
        "receivedAt": ts,
        "xmlPayload": xml_str,
        "source": "simulator",
        "forwardResult": maybe_forward_to_sunguide("/v1/alert", xml_str),
    }
    store_and_broadcast(entry)
    return jsonify({"alertId": alert_id, "xml": xml_str})


@app.route("/api/devices/<did>/update", methods=["POST"])
def api_generate_update(did):
    """Simulate the WWVDS device sending a follow-up image update."""
    with devices_lock:
        dev = devices.get(did)
    if not dev:
        return jsonify({"error": "Device not found"}), 404

    body = request.get_json(force=True) or {}
    alert_id = (body.get("alertId") or "").strip()
    if not alert_id:
        return jsonify({"error": "alertId is required"}), 400

    ts = iso_now()

    if dev.get("snapshotSet"):
        images = snapshot_urls(dev["snapshotSet"], dev["numSnapshots"])
    else:
        num_images = int(body.get("numImages", random.randint(1, 3)))
        num_images = max(1, min(10, num_images))
        images = [f"http://{dev['ipAddress']}/images/{alert_id}/update_{i+1:02d}.jpg" for i in range(num_images)]

    update_data = {
        "alertId": alert_id,
        "deviceId": did,
        "updateTimestamp": ts,
        "images": images,
    }
    xml_str = build_update_xml(update_data)

    entry = {
        "type": "update",
        **update_data,
        "receivedAt": ts,
        "xmlPayload": xml_str,
        "source": "simulator",
        "forwardResult": maybe_forward_to_sunguide("/v1/update", xml_str),
    }
    store_and_broadcast(entry)
    return jsonify({"alertId": alert_id, "xml": xml_str})


# ─── Event Log API ────────────────────────────────────────────────────────────

@app.route("/api/alerts")
def api_list_alerts():
    with log_lock:
        return jsonify(list(reversed(event_log)))


@app.route("/api/alerts", methods=["DELETE"])
def api_clear_alerts():
    with log_lock:
        event_log.clear()
    return "", 204


# ─── Settings API ─────────────────────────────────────────────────────────────

@app.route("/api/settings", methods=["GET"])
def api_get_settings():
    return jsonify(settings)


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.get_json(force=True)
    settings["sunguideUrl"] = (data.get("sunguideUrl") or "").strip()
    settings["forwardToSunguide"] = bool(data.get("forwardToSunguide", False))
    settings["snapshotBaseUrl"] = (data.get("snapshotBaseUrl") or "").strip()
    save_config()
    return jsonify(settings)


# ─── SSE ─────────────────────────────────────────────────────────────────────

@app.route("/api/events")
def sse():
    q: queue.Queue = queue.Queue(maxsize=200)
    with queues_lock:
        sse_queues.append(q)

    def generate():
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            with queues_lock:
                try:
                    sse_queues.remove(q)
                except ValueError:
                    pass

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── UI ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template(
        "index.html",
        directions=DIRECTIONS,
        statuses=DEVICE_STATUSES,
    )


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_config()
    print("WWVDS SunGuide Protocol Simulator")
    print("  Web UI:         http://localhost:5000/")
    print("  Status API:     GET  http://localhost:5000/v1/status?DeviceId=<id>")
    print("  Alert receiver: POST http://localhost:5000/v1/alert")
    print("  Update receiver:POST http://localhost:5000/v1/update")
    app.run(host="0.0.0.0", port=5000, threaded=True)
