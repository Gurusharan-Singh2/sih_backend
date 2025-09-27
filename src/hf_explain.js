const axios = require("axios");

const HF_API_URL = "https://api-inference.huggingface.co/models/gpt2";
const HF_TOKEN = process.env.HF_API_TOKEN;

async function explainAlertHF(alert) {
  const prompt = `
You are a cybersecurity assistant. Explain this SOC alert to a security engineer:

Title: ${alert.title}
Severity: ${alert.severity}
Type: ${alert.type}
Evidence: ${JSON.stringify(alert.evidence)}

Please provide:
- A simple summary
- Why it's important
- Suggested remediation
`;

  try {
    const resp = await axios.post(
      HF_API_URL,
      { inputs: prompt },
      {
        headers: {
          Authorization: `Bearer ${HF_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    const data = resp.data;
    if (Array.isArray(data) && data[0]?.generated_text) {
      return data[0].generated_text;
    }
    return JSON.stringify(data);
  } catch (err) {
    console.error("HF explain error:", err.response?.data || err.message);
    throw err;
  }
}

module.exports = { explainAlertHF };