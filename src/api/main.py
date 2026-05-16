"""
IoT anomaly detection API: ingest flows, classify, stream results to UI.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.schemas import DetectionEvent, NetworkFlow, PredictRequest, StatsResponse
from api.store import EventStore
from inference import FlowClassifier
from read_dataset import expand_label_columns, iter_batches, project_data_dir

STATIC_DIR = Path(__file__).resolve().parent.parent / "web" / "static"

store = EventStore()
classifier: FlowClassifier | None = None
simulator_task: asyncio.Task | None = None
ws_clients: set[WebSocket] = set()


async def broadcast(events: list[dict]) -> None:
    if not ws_clients:
        return
    payload = json.dumps({"type": "detections", "events": events}, default=str)
    dead: list[WebSocket] = []
    for client in ws_clients:
        try:
            await client.send_text(payload)
        except Exception:
            dead.append(client)
    for client in dead:
        ws_clients.discard(client)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global classifier
    classifier = FlowClassifier()
    yield
    global simulator_task
    if simulator_task and not simulator_task.done():
        simulator_task.cancel()
        try:
            await simulator_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="IoT Anomaly Detection",
    description="API for IoT network flow classification (benign / malicious)",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return {"message": "UI not found. Build web/static/index.html"}


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": classifier is not None,
        "model_path": str(classifier.model_path) if classifier else None,
    }


@app.get("/api/stats", response_model=StatsResponse)
async def stats():
    data = store.stats()
    return StatsResponse(
        **data,
        model_path=str(classifier.model_path) if classifier else "",
    )


@app.get("/api/events")
async def events(limit: int = 100):
    return store.list_events(limit=limit)


@app.post("/api/predict", response_model=list[DetectionEvent])
async def predict(body: PredictRequest):
    assert classifier is not None
    flow_dicts = [flow.to_feature_dict() for flow in body.flows]
    results = classifier.predict(flow_dicts)
    store.add_many(results)
    await broadcast(results)
    return results


@app.post("/api/ingest", response_model=list[DetectionEvent])
async def ingest(body: PredictRequest):
    """Alias for device data collection endpoint."""
    return await predict(body)


@app.delete("/api/events")
async def clear_events():
    store.clear()
    await broadcast([{"type": "cleared"}])
    return {"ok": True}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.add(websocket)
    try:
        await websocket.send_json(
            {
                "type": "hello",
                "events": store.list_events(50),
                "stats": store.stats(),
            }
        )
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_clients.discard(websocket)


DEVICE_NAMES = [
    "philips-hue",
    "amazon-echo",
    "somfy-lock",
    "raspberry-malware",
    "camera-01",
]


async def run_simulator(interval_sec: float = 1.5, rows_per_tick: int = 3) -> None:
    assert classifier is not None
    data_dir = project_data_dir()
    logs = list(data_dir.rglob("conn.log.labeled"))
    if not logs:
        return

    log_path = min(logs, key=lambda path: path.stat().st_size if path.exists() else 0)
    batch_iter = iter_batches(log_path, batch_size=500)
    tick = 0

    while True:
        try:
            batch = next(batch_iter)
        except StopIteration:
            batch_iter = iter_batches(log_path, batch_size=500)
            batch = next(batch_iter)

        batch = expand_label_columns(batch)
        sample = batch.sample(min(rows_per_tick, batch.height), shuffle=True)
        flows = []
        for row in sample.iter_rows(named=True):
            device = DEVICE_NAMES[tick % len(DEVICE_NAMES)]
            flows.append(
                {
                    "device_id": device,
                    "ts": row.get("ts"),
                    "proto": row.get("proto") or "tcp",
                    "service": row.get("service") or "-",
                    "duration": row.get("duration"),
                    "orig_bytes": row.get("orig_bytes"),
                    "resp_bytes": row.get("resp_bytes"),
                    "missed_bytes": row.get("missed_bytes"),
                    "orig_pkts": row.get("orig_pkts"),
                    "orig_ip_bytes": row.get("orig_ip_bytes"),
                    "resp_pkts": row.get("resp_pkts"),
                    "resp_ip_bytes": row.get("resp_ip_bytes"),
                    "id.orig_p": row.get("id.orig_p"),
                    "id.resp_p": row.get("id.resp_p"),
                    "conn_state": row.get("conn_state") or "S0",
                    "id.resp_h": row.get("id.resp_h"),
                }
            )
        tick += 1

        results = classifier.predict(flows)
        store.add_many(results)
        await broadcast(results)
        await asyncio.sleep(interval_sec)


@app.post("/api/simulator/start")
async def start_simulator(interval_sec: float = 1.5):
    global simulator_task
    if simulator_task and not simulator_task.done():
        return {"running": True, "message": "Simulator already running"}
    simulator_task = asyncio.create_task(run_simulator(interval_sec=interval_sec))
    return {"running": True, "interval_sec": interval_sec}


@app.post("/api/simulator/stop")
async def stop_simulator():
    global simulator_task
    if simulator_task and not simulator_task.done():
        simulator_task.cancel()
        try:
            await simulator_task
        except asyncio.CancelledError:
            pass
    simulator_task = None
    return {"running": False}
