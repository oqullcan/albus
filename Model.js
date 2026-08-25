// reactive state model and debloated runtime parser for albus dpi

.pragma library

var daemonStatus = {
  active: false,
  totalConnections: 0,
  tlsBypassed: 0,
  httpBypassed: 0,
  bytesProtected: 0,
  bytesProtectedStr: "0 B",
  latency: 0,
  activeDns: "Quad9",
  onBattery: false,
  history: [],
  events: []
};

function parseStatus(rawJson) {
  if (!rawJson || typeof rawJson !== "string" || rawJson.trim() === "") {
    return false;
  }
  try {
    var data = JSON.parse(rawJson.trim());
    if (data.running !== undefined) {
      daemonStatus.active = Boolean(data.running);
      daemonStatus.totalConnections = Number(data.total) || 0;
      daemonStatus.tlsBypassed = Number(data.tls) || 0;
      daemonStatus.httpBypassed = Number(data.http) || 0;
      daemonStatus.bytesProtected = Number(data.bytes) || 0;
      daemonStatus.bytesProtectedStr = data.bytes_str ? String(data.bytes_str) : "0 B";
      daemonStatus.latency = Number(data.latency) || 0;
      daemonStatus.onBattery = Boolean(data.battery);
      if (data.dns) {
        daemonStatus.activeDns = String(data.dns);
      }
      if (Array.isArray(data.history)) {
        daemonStatus.history = data.history;
      }
      if (Array.isArray(data.events)) {
        daemonStatus.events = data.events;
      }
      return true;
    }
  } catch (e) {
    // ignore transient json formatting glitches
  }
  return false;
}

function parseConfig(rawJson) {
  if (!rawJson || typeof rawJson !== "string" || rawJson.trim() === "") {
    return null;
  }
  try {
    return JSON.parse(rawJson.trim());
  } catch (e) {
    return null;
  }
}

function parseDiagnostic(rawJson) {
  if (!rawJson || typeof rawJson !== "string" || rawJson.trim() === "") {
    return null;
  }
  try {
    return JSON.parse(rawJson.trim());
  } catch (e) {
    return null;
  }
}

function getStatus() {
  return daemonStatus;
}
