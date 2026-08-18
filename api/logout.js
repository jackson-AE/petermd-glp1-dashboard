module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  res.setHeader("Set-Cookie", "pmd_auth=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  res.status(200).json({ ok: true });
};
