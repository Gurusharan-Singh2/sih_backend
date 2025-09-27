const express = require("express");
const { v4: uuidv4 } = require("uuid");
const { Event, Alert, Remediation } = require("./db");
const { runDetectors } = require("./detector");
const { explainAlertHF } = require("./hf_explain");

const router = express.Router();

router.post("/ingest", async (req, res) => {
  const events = Array.isArray(req.body) ? req.body : [req.body];
  const alerts = [];

  for (const e of events) {
    const event = { id: uuidv4(), ...e };
    await Event.create(event);

    const alert = runDetectors(event);
    if (alert) {
      await Alert.create(alert);
      alerts.push(alert);
    }
  }

  res.json({ ok: true, created_alerts: alerts });
});

router.get("/alerts", async (req, res) => {
  const alerts = await Alert.find().sort({ timestamp: -1 }).lean();
  res.json(alerts);
});

router.post("/remediate", async (req, res) => {
  const { alert_id, action, reason } = req.body;
  const alert = await Alert.findOne({ id: alert_id });
  if (!alert) return res.status(404).json({ error: "alert not found" });

  const remediation = await Remediation.create({
    id: uuidv4(),
    alert_id,
    action,
    meta: { reason },
    timestamp: new Date().toISOString(),
    status: "applied",
  });

  res.json({ ok: true, remediation });
});

router.get("/explain/:alert_id", async (req, res) => {
  const alert = await Alert.findOne({ id: req.params.alert_id });
  if (!alert) return res.status(404).json({ error: "alert not found" });

  try {
    const explanation = await explainAlertHF(alert);
    res.json({ alert, explanation });
  } catch (err) {
    res.status(500).json({ error: "HF API error", details: err.message });
  }
});

module.exports = router;