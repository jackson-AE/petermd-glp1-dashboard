const https = require("https");
const fs = require("fs");
const crypto = require("crypto");

const CONFIG = {
  spreadsheetId: process.env.PETERMD_SPREADSHEET_ID || "1pNGN8v3Q_1WSdpwwdvyZ25vlGFAVZifCBtJgCF7Etrw",
  appsScriptUrl: process.env.PETERMD_APPS_SCRIPT_URL || "",
  appsScriptSecret: process.env.PETERMD_APPS_SCRIPT_SECRET || "",
  dashboardPassword: process.env.PETERMD_DASHBOARD_PASSWORD || "",
};

let tokenCache = null;
let lastGoodFunnelData = null;

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requestJson(method, url, { headers = {}, body = null, redirects = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          if (redirects >= 5) {
            reject(new Error("Too many redirects while loading funnel data"));
            return;
          }
          const nextUrl = new URL(res.headers.location, url).toString();
          requestJson("GET", nextUrl, { headers, redirects: redirects + 1 }).then(resolve).catch(reject);
          return;
        }

        let parsed = null;
        try { parsed = data ? JSON.parse(data) : null; }
        catch (err) {
          reject(new Error("Invalid JSON response"));
          return;
        }

        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error((parsed && (parsed.error || parsed.message)) || `API error ${res.statusCode}`));
          return;
        }

        resolve(parsed);
      });
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function parseCookies(header) {
  return String(header || "").split(";").reduce((cookies, part) => {
    const index = part.indexOf("=");
    if (index > -1) cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    return cookies;
  }, {});
}

function signSession(timestamp) {
  return crypto.createHmac("sha256", CONFIG.dashboardPassword).update(String(timestamp)).digest("hex");
}

function hasValidSession(req) {
  if (!CONFIG.dashboardPassword) return false;
  const token = parseCookies(req.headers.cookie).pmd_auth || "";
  const [timestamp, signature] = token.split(".");
  if (!timestamp || !signature) return false;
  const ageMs = Date.now() - Number(timestamp);
  if (!Number.isFinite(ageMs) || ageMs < 0 || ageMs > 12 * 60 * 60 * 1000) return false;
  const expected = signSession(timestamp);
  if (signature.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function loadServiceAccount() {
  if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON) {
    const json = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
    if (json.private_key) json.private_key = json.private_key.replace(/\\n/g, "\n");
    return json;
  }
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    const json = JSON.parse(fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, "utf8"));
    if (json.private_key) json.private_key = json.private_key.replace(/\\n/g, "\n");
    return json;
  }
  throw new Error("Missing Google credentials.");
}

async function getAccessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (tokenCache && tokenCache.expiresAt > now + 60) return tokenCache.accessToken;

  const sa = loadServiceAccount();
  const tokenUri = sa.token_uri || "https://oauth2.googleapis.com/token";
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/spreadsheets.readonly",
    aud: tokenUri,
    iat: now,
    exp: now + 3600,
  }));
  const unsigned = `${header}.${payload}`;
  const signature = crypto.createSign("RSA-SHA256").update(unsigned).sign(sa.private_key, "base64url");
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: `${unsigned}.${signature}`,
  }).toString();

  const token = await requestJson("POST", tokenUri, {
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) },
    body,
  });
  tokenCache = { accessToken: token.access_token, expiresAt: now + Number(token.expires_in || 3600) };
  return tokenCache.accessToken;
}

function rowsToObjects(values) {
  const headers = (values[0] || []).map((header) => String(header || "").trim());
  return values.slice(1).map((row) => {
    const obj = {};
    headers.forEach((header, index) => {
      if (header) obj[header] = row[index] == null ? "" : row[index];
    });
    return obj;
  }).filter((row) => Object.values(row).some((value) => String(value || "").trim()));
}

async function loadFromAppsScript() {
  const url = new URL(CONFIG.appsScriptUrl);
  url.searchParams.set("key", CONFIG.appsScriptSecret);
  url.searchParams.set("dataset", "funnel");
  let lastError = null;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const payload = await requestJson("GET", url.toString());
      if (payload.error) {
        throw new Error([payload.error, payload.detail].filter(Boolean).join(": "));
      }

      const data = {
        gaRows: payload.gaRows || [],
        embRows: payload.embRows || [],
        dataUpdatedAt: payload.dataUpdatedAt || "",
        stale: false,
      };
      lastGoodFunnelData = data;
      return data;
    } catch (err) {
      lastError = err;
      if (attempt < 3) await wait(700 * attempt);
    }
  }

  if (lastGoodFunnelData) {
    return Object.assign({}, lastGoodFunnelData, {
      stale: true,
      warning: `Using last loaded data because Apps Script failed: ${lastError && lastError.message ? lastError.message : lastError}`,
    });
  }

  throw lastError || new Error("Apps Script funnel data could not be loaded.");
}

async function loadSheetRange(accessToken, sheetName) {
  const a1 = `'${sheetName.replace(/'/g, "''")}'`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(CONFIG.spreadsheetId)}/values/${encodeURIComponent(a1)}?majorDimension=ROWS`;
  const data = await requestJson("GET", url, { headers: { Authorization: `Bearer ${accessToken}` } });
  return rowsToObjects(data.values || []);
}

async function loadFromSheetsApi() {
  const accessToken = await getAccessToken();
  const [gaRows, embRows] = await Promise.all([
    loadSheetRange(accessToken, "ga_db"),
    loadSheetRange(accessToken, "emb_db"),
  ]);
  return {
    gaRows,
    embRows,
    dataUpdatedAt: "",
    stale: false,
  };
}

async function loadFunnelData() {
  if (CONFIG.appsScriptUrl && CONFIG.appsScriptSecret) {
    return loadFromAppsScript();
  }
  return loadFromSheetsApi();
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  try {
    const data = await loadFunnelData();
    res.setHeader("Cache-Control", "no-store");
    res.status(200).json({
      gaRows: data.gaRows,
      embRows: data.embRows,
      dataUpdatedAt: data.dataUpdatedAt,
      updatedAt: data.dataUpdatedAt,
      stale: Boolean(data.stale),
      warning: data.warning || "",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Funnel dashboard data could not be loaded.",
      detail: err && err.message ? err.message : String(err),
    });
  }
};
