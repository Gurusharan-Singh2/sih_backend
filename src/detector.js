const { v4: uuidv4 } = require("uuid");

const ipFailedCounts = new Map();
const userDownloadCounts = new Map();

function makeAlert({ title, severity, type, evidence }) {
  return {
    id: uuidv4(),
    title,
    severity,
    type,
    evidence,
    timestamp: new Date().toISOString(),
  };
}

function detectBruteForce(event) {
  if (event.type !== "auth" || event.action !== "login_failure") return null;
  const key = event.source_ip;
  const now = Date.now();
  const windowMs = 5 * 60 * 1000;

  const list = ipFailedCounts.get(key) || [];
  list.push(now);
  const filtered = list.filter(ts => now - ts <= windowMs);
  ipFailedCounts.set(key, filtered);

  if (filtered.length >= 5) {
    return makeAlert({
      title: "Brute force login attempts detected",
      severity: "high",
      type: "brute_force",
      evidence: { source_ip: event.source_ip, attempts: filtered.length },
    });
  }
  if (filtered.length >= 3) {
    return makeAlert({
      title: "Suspicious login failures",
      severity: "medium",
      type: "brute_force",
      evidence: { source_ip: event.source_ip, attempts: filtered.length },
    });
  }
  return null;
}

function detectPrivilegeMisuse(event) {
  if (event.type !== "audit") return null;
  const sensitive = ["role_change", "permission_grant", "sensitive_config_change"];
  if (!sensitive.includes(event.action)) return null;

  const hour = new Date(event.timestamp || Date.now()).getUTCHours();
  const evidence = { user: event.user, action: event.action, hour };

  if (hour < 8 || hour > 18) {
    return makeAlert({
      title: "Potential insider misuse (out-of-hours sensitive action)",
      severity: "medium",
      type: "insider_misuse",
      evidence,
    });
  }
  return makeAlert({
    title: "Sensitive privileged action detected",
    severity: "low",
    type: "insider_misuse",
    evidence,
  });
}

function detectDataExfil(event) {
  if (event.type !== "file" && event.type !== "network") return null;

  if (event.bytes_out && event.bytes_out > 50 * 1024 * 1024) {
    return makeAlert({
      title: "Large outbound transfer (possible exfiltration)",
      severity: "high",
      type: "data_exfil",
      evidence: { bytes_out: event.bytes_out, dst: event.dst },
    });
  }

  if (event.type === "file" && event.action === "download") {
    const key = event.user;
    const now = Date.now();
    const list = userDownloadCounts.get(key) || [];
    list.push(now);
    const filtered = list.filter(ts => now - ts <= 10 * 60 * 1000);
    userDownloadCounts.set(key, filtered);

    if (filtered.length >= 20) {
      return makeAlert({
        title: "Unusually high number of downloads (possible exfil)",
        severity: "high",
        type: "data_exfil",
        evidence: { user: event.user, count: filtered.length },
      });
    }
    if (filtered.length >= 8) {
      return makeAlert({
        title: "High download rate",
        severity: "medium",
        type: "data_exfil",
        evidence: { user: event.user, count: filtered.length },
      });
    }
  }
  return null;
}

function detectMalware(event) {
  if (event.type === "endpoint" && event.action === "process_create") {
    if (/\b(psexec|wmic|powershell)\b/i.test(event.process)) {
      return makeAlert({
        title: "Suspicious process (possible malware)",
        severity: "medium",
        type: "malware",
        evidence: { process: event.process, user: event.user },
      });
    }
  }
  if (event.type === "endpoint" && event.file_hash && event.file_hash.length >= 32) {
    return makeAlert({
      title: "Unknown file hash observed",
      severity: "low",
      type: "malware",
      evidence: { file_hash: event.file_hash },
    });
  }
  if (event.type === "network" && event.action === "outbound_connection") {
    if (event.dst && /\.ru$|\.cn$|\.biz$/.test(event.dst)) {
      return makeAlert({
        title: "Suspicious outbound connection (possible C2)",
        severity: "medium",
        type: "malware",
        evidence: { dst: event.dst, port: event.port },
      });
    }
  }
  return null;
}

function runDetectors(event) {
  const detectors = [detectBruteForce, detectPrivilegeMisuse, detectDataExfil, detectMalware];
  for (const d of detectors) {
    const a = d(event);
    if (a) return a;
  }
  return null;
}

module.exports = { runDetectors };