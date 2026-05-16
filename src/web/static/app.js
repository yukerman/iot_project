const API = window.location.origin;
const WS_URL = `${window.location.protocol === "https:" ? "wss" : "ws"}://${window.location.host}/ws`;

const els = {
  status: document.getElementById("connectionStatus"),
  total: document.getElementById("statTotal"),
  benign: document.getElementById("statBenign"),
  malicious: document.getElementById("statMalicious"),
  devices: document.getElementById("statDevices"),
  eventsBody: document.getElementById("eventsBody"),
  modelPath: document.getElementById("modelPath"),
  form: document.getElementById("flowForm"),
  startSim: document.getElementById("startSim"),
  stopSim: document.getElementById("stopSim"),
  clearEvents: document.getElementById("clearEvents"),
};

function formatTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return date.toLocaleTimeString("ru-RU");
}

function renderStats(stats) {
  els.total.textContent = stats.total ?? 0;
  els.benign.textContent = stats.benign ?? 0;
  els.malicious.textContent = stats.malicious ?? 0;
  els.devices.textContent = stats.devices ?? 0;
}

function renderEventRow(event) {
  const tr = document.createElement("tr");
  if (event.prediction === "malicious") {
    tr.classList.add("row-malicious");
  }
  const prob =
    event.prediction === "malicious"
      ? event.probability_malicious
      : event.probability_benign;

  tr.innerHTML = `
    <td>${formatTime(event.received_at)}</td>
    <td>${event.device_id}</td>
    <td>${event.proto ?? "—"}</td>
    <td>${(prob * 100).toFixed(1)}%</td>
    <td><span class="badge ${event.prediction}">${event.prediction}</span></td>
  `;
  return tr;
}

function prependEvents(events) {
  for (const event of events) {
    els.eventsBody.prepend(renderEventRow(event));
  }
  while (els.eventsBody.children.length > 200) {
    els.eventsBody.lastChild.remove();
  }
}

function setConnectionStatus(online) {
  els.status.textContent = online ? "Онлайн" : "Офлайн";
  els.status.classList.toggle("offline", !online);
}

async function refreshStats() {
  const response = await fetch(`${API}/api/stats`);
  const stats = await response.json();
  renderStats(stats);
  if (stats.model_path) {
    els.modelPath.textContent = `Модель: ${stats.model_path}`;
  }
}

async function loadEvents() {
  const response = await fetch(`${API}/api/events?limit=100`);
  const events = await response.json();
  els.eventsBody.innerHTML = "";
  events.reverse().forEach((event) => prependEvents([event]));
}

function connectWebSocket() {
  const socket = new WebSocket(WS_URL);

  socket.addEventListener("open", () => setConnectionStatus(true));
  socket.addEventListener("close", () => {
    setConnectionStatus(false);
    setTimeout(connectWebSocket, 2000);
  });

  socket.addEventListener("message", (message) => {
    const payload = JSON.parse(message.data);
    if (payload.type === "hello") {
      renderStats(payload.stats);
      els.eventsBody.innerHTML = "";
      payload.events.reverse().forEach((event) => prependEvents([event]));
    }
    if (payload.type === "detections") {
      prependEvents(payload.events);
      refreshStats();
    }
    if (payload.type === "cleared") {
      els.eventsBody.innerHTML = "";
      refreshStats();
    }
  });
}

els.form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const formData = new FormData(els.form);
  const flow = Object.fromEntries(formData.entries());
  flow["id.resp_p"] = Number(flow["id.resp_p"]);
  flow.orig_bytes = Number(flow.orig_bytes);
  flow.resp_bytes = Number(flow.resp_bytes);

  const response = await fetch(`${API}/api/ingest`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ flows: [flow] }),
  });
  const results = await response.json();
  prependEvents(results);
  refreshStats();
});

els.startSim.addEventListener("click", async () => {
  await fetch(`${API}/api/simulator/start?interval_sec=1.2`, { method: "POST" });
});

els.stopSim.addEventListener("click", async () => {
  await fetch(`${API}/api/simulator/stop`, { method: "POST" });
});

els.clearEvents.addEventListener("click", async () => {
  await fetch(`${API}/api/events`, { method: "DELETE" });
  els.eventsBody.innerHTML = "";
  refreshStats();
});

async function init() {
  try {
    const health = await fetch(`${API}/api/health`);
    const info = await health.json();
    if (info.model_path) {
      els.modelPath.textContent = `Модель: ${info.model_path}`;
    }
  } catch {
    setConnectionStatus(false);
  }
  await refreshStats();
  connectWebSocket();
}

init();
