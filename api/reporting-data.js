const https = require("https");
const fs = require("fs");
const crypto = require("crypto");

const CONFIG = {
  spreadsheetId: process.env.PETERMD_SPREADSHEET_ID || "1pNGN8v3Q_1WSdpwwdvyZ25vlGFAVZifCBtJgCF7Etrw",
  reportingDataGid: Number(process.env.PETERMD_REPORTING_DATA_GID || 372008856),
  appsScriptUrl: process.env.PETERMD_APPS_SCRIPT_URL || "",
  appsScriptSecret: process.env.PETERMD_APPS_SCRIPT_SECRET || "",
  appsScriptOffer: process.env.PETERMD_APPS_SCRIPT_OFFER || "GLP1",
  appsScriptColumns: process.env.PETERMD_APPS_SCRIPT_COLUMNS || "marketing",
  appsScriptTimeoutMs: Number(process.env.PETERMD_APPS_SCRIPT_TIMEOUT_MS || 15000),
  appsScriptAttempts: Number(process.env.PETERMD_APPS_SCRIPT_ATTEMPTS || 1),
  dashboardPassword: process.env.PETERMD_DASHBOARD_PASSWORD || "",
};

let tokenCache = null;
let sheetTitleCache = null;
let lastGoodReportingData = null;

const DATE_FIELDS = ["Date", "Customer Sale Date", "Customer Lead Date", "Sale Date", "Lead Date"];
const DAY_MS = 24 * 60 * 60 * 1000;

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
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

function requestJson(method, url, { headers = {}, body = null, redirects = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request(url, { method, headers }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
          if (redirects >= 5) {
            reject(new Error("Too many redirects while loading dashboard data"));
            return;
          }
          const nextUrl = new URL(res.headers.location, url).toString();
          requestJson("GET", nextUrl, { headers, redirects: redirects + 1 }).then(resolve).catch(reject);
          return;
        }

        let parsed = null;
        try { parsed = data ? JSON.parse(data) : null; }
        catch (err) { reject(new Error("Invalid JSON response from Google")); return; }
        if (res.statusCode < 200 || res.statusCode >= 300) {
          reject(new Error((parsed && parsed.error && parsed.error.message) || `Google API error ${res.statusCode}`));
          return;
        }
        resolve(parsed);
      });
    });
    req.on("error", reject);
    req.setTimeout(CONFIG.appsScriptTimeoutMs, () => {
      req.destroy(new Error(`Google Apps Script timed out after ${CONFIG.appsScriptTimeoutMs}ms`));
    });
    if (body) req.write(body);
    req.end();
  });
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
  const assertion = `${unsigned}.${signature}`;
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
  }).toString();

  const token = await requestJson("POST", tokenUri, {
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": Buffer.byteLength(body) },
    body,
  });
  tokenCache = { accessToken: token.access_token, expiresAt: now + Number(token.expires_in || 3600) };
  return tokenCache.accessToken;
}

function quoteSheetTitle(title) {
  return `'${String(title).replace(/'/g, "''")}'`;
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

async function getReportingSheetTitle(accessToken) {
  if (sheetTitleCache) return sheetTitleCache;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(CONFIG.spreadsheetId)}?fields=sheets.properties(sheetId,title)`;
  const meta = await requestJson("GET", url, { headers: { Authorization: `Bearer ${accessToken}` } });
  const sheet = (meta.sheets || []).map((s) => s.properties).find((p) => Number(p.sheetId) === CONFIG.reportingDataGid);
  if (!sheet) throw new Error(`Could not find sheet tab with gid ${CONFIG.reportingDataGid}`);
  sheetTitleCache = sheet.title;
  return sheetTitleCache;
}

function rowsToObjects(values) {
  const headers = (values[0] || []).map((h) => String(h || "").trim());
  return values.slice(1).map((row) => {
    const obj = {};
    headers.forEach((header, index) => {
      if (header) obj[header] = row[index] == null ? "" : row[index];
    });
    return obj;
  }).filter((row) => Object.values(row).some((value) => String(value || "").trim()));
}

function isoFromParts(year, month, day) {
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function normalizeDateValue(value) {
  if (value == null || value === "") return "";

  const s = String(value).trim();
  if (!s) return "";

  if (/^\d+(\.\d+)?$/.test(s)) {
    const serial = Number(s);
    if (serial > 20000 && serial < 80000) {
      const d = new Date(Math.round((serial - 25569) * DAY_MS));
      return isoFromParts(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
    }
  }

  const iso = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (iso) return isoFromParts(Number(iso[1]), Number(iso[2]), Number(iso[3]));

  return value;
}

function normalizeReportingRows(rows) {
  return (rows || []).map((row) => {
    const next = Object.assign({}, row);
    DATE_FIELDS.forEach((field) => {
      if (Object.prototype.hasOwnProperty.call(next, field)) {
        next[field] = normalizeDateValue(next[field]);
      }
    });
    return next;
  });
}

async function loadReportingData() {
  if (CONFIG.appsScriptUrl && CONFIG.appsScriptSecret) {
    const url = new URL(CONFIG.appsScriptUrl);
    url.searchParams.set("key", CONFIG.appsScriptSecret);
    if (CONFIG.appsScriptOffer) url.searchParams.set("offer", CONFIG.appsScriptOffer);
    if (CONFIG.appsScriptColumns) url.searchParams.set("columns", CONFIG.appsScriptColumns);
    let lastError = null;

    for (let attempt = 1; attempt <= CONFIG.appsScriptAttempts; attempt += 1) {
      try {
        const payload = await requestJson("GET", url.toString());
        if (payload.error) {
          throw new Error([payload.error, payload.detail].filter(Boolean).join(": "));
        }

        const data = {
          rows: normalizeReportingRows(payload.rows || []),
          dataUpdatedAt: payload.dataUpdatedAt || "",
          stale: false,
        };
        lastGoodReportingData = data;
        return data;
      } catch (err) {
        lastError = err;
        if (attempt < CONFIG.appsScriptAttempts) await wait(700 * attempt);
      }
    }

    if (lastGoodReportingData) {
      return Object.assign({}, lastGoodReportingData, {
        stale: true,
        warning: `Using last loaded data because Apps Script failed: ${lastError && lastError.message ? lastError.message : lastError}`,
      });
    }

    throw lastError || new Error("Apps Script dashboard data could not be loaded.");
  }

  const accessToken = await getAccessToken();
  const sheetTitle = await getReportingSheetTitle(accessToken);
  const a1 = quoteSheetTitle(sheetTitle);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(CONFIG.spreadsheetId)}/values/${encodeURIComponent(a1)}?majorDimension=ROWS`;
  const data = await requestJson("GET", url, { headers: { Authorization: `Bearer ${accessToken}` } });
  return {
    rows: normalizeReportingRows(rowsToObjects(data.values || [])),
    dataUpdatedAt: "",
    stale: false,
  };
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  try {
    const data = await loadReportingData();
    res.setHeader("Cache-Control", "no-store");
    res.status(200).json({
      rows: data.rows,
      dataUpdatedAt: data.dataUpdatedAt,
      updatedAt: data.dataUpdatedAt,
      stale: Boolean(data.stale),
      warning: data.warning || "",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      error: "Dashboard data could not be loaded.",
      detail: err && err.message ? err.message : String(err),
    });
  }
};
