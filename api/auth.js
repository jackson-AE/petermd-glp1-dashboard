const crypto = require("crypto");

const DASHBOARD_PASSWORD = process.env.PETERMD_DASHBOARD_PASSWORD || "";

function signSession(timestamp) {
  return crypto.createHmac("sha256", DASHBOARD_PASSWORD).update(String(timestamp)).digest("hex");
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 10000) reject(new Error("Request body too large"));
    });
    req.on("end", () => {
      try { resolve(body ? JSON.parse(body) : {}); }
      catch (err) { reject(new Error("Invalid JSON")); }
    });
    req.on("error", reject);
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  if (!DASHBOARD_PASSWORD) {
    res.status(500).json({ error: "PeterMD dashboard password is not configured." });
    return;
  }

  try {
    const body = await readJson(req);
    const password = String(body.password || "");
    const valid = password.length === DASHBOARD_PASSWORD.length &&
      crypto.timingSafeEqual(Buffer.from(password), Buffer.from(DASHBOARD_PASSWORD));

    if (!valid) {
      res.status(401).json({ error: "Wrong password." });
      return;
    }

    const timestamp = Date.now();
    const token = `${timestamp}.${signSession(timestamp)}`;
    res.setHeader("Set-Cookie", `pmd_auth=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200`);
    res.status(200).json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: "Login could not be processed." });
  }
};
