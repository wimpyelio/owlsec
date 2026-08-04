import express from "express";
import { scanHandler } from "./routes/scan.js";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(express.json());

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/scan", scanHandler);

// Production: serve built SPA
const distPath = path.resolve(__dirname, "../dist");
app.use(express.static(distPath));

app.get("{*path}", (_req, res) => {
  res.sendFile(path.join(distPath, "index.html"));
});

const PORT = process.env.PORT ?? 3001;

app.listen(PORT, () => {
  console.log(`Express server listening on http://localhost:${PORT}`);
});

export default app;
