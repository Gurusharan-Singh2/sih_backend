const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const routes = require("./routes");
const { initDB } = require("./db");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use("/", routes);

const PORT = process.env.PORT || 3005;

(async () => {
  await initDB();
  app.listen(PORT, () => console.log(`🚀 Smart SOC backend running on port ${PORT}`));
})();