import express from "express";

const app = express();

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok" });
});

const PORT = process.env.PORT ?? 3001;

app.listen(PORT, () => {
  console.log(`Express server listening on http://localhost:${PORT}`);
});

export default app;