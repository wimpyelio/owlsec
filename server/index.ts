import express from "express";
import { scanHandler } from "./routes/scan.js";

const app = express();

app.use(express.json());

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/scan", scanHandler);

const PORT = process.env.PORT ?? 3001;

app.listen(PORT, () => {
  console.log(`Express server listening on http://localhost:${PORT}`);
});

export default app;