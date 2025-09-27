const mongoose = require("mongoose");

async function initDB() {
  const mongoUri = process.env.MONGO_URI || "mongodb+srv://guru63920_db_user:B7LOAIE0UpAE0ypJ@sih.peord7g.mongodb.net/smart_soc";
  await mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log("✅ Connected to MongoDB");
}

const eventSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: String,
  user: String,
  source_ip: String,
  action: String,
  bytes_out: Number,
  process: String,
  file_hash: String,
  dst: String,
  port: Number,
  timestamp: String,
});

const alertSchema = new mongoose.Schema({
  id: { type: String, required: true },
  title: String,
  severity: String,
  type: String,
  evidence: mongoose.Schema.Types.Mixed,
  timestamp: String,
});

const remediationSchema = new mongoose.Schema({
  id: { type: String, required: true },
  alert_id: String,
  action: String,
  meta: mongoose.Schema.Types.Mixed,
  timestamp: String,
  status: String,
});

const Event = mongoose.model("Event", eventSchema);
const Alert = mongoose.model("Alert", alertSchema);
const Remediation = mongoose.model("Remediation", remediationSchema);

module.exports = { initDB, Event, Alert, Remediation };