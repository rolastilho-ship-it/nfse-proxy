import express from "express";
import fetch from "node-fetch";

const app = express();
app.use(express.json({ limit: "10mb" }));

const PROXY_TOKEN = process.env.NFSE_PROXY_TOKEN || "";

function checkAuth(req, res) {
  if (!PROXY_TOKEN) return true;
  if (req.headers["x-proxy-token"] !== PROXY_TOKEN) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

const URLS = {
  producao: {
    token: "https://autenticacao.nfse.gov.br/oauth/token",
    dps: "https://adn.nfse.gov.br/contribuintes/dps",
  },
  homologacao: {
    token: "https://autenticacao.producaorestrita.nfse.gov.br/oauth/token",
    dps: "https://adn.producaorestrita.nfse.gov.br/contribuintes/dps",
  }
};

async function autenticar(cpf, senha, ambiente) {
  const url = URLS[ambiente]?.token;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "password",
      username: cpf.replace(/\D/g, ""),
      password: senha,
      client_id: "nfse-emissor-contribuinte",
      scope: "openid profile email"
    }).toString()
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Autenticação gov.br falhou: ${err}`);
  }
  const data = await res.json();
  return data.access_token;
}

// Health check
app.get("/health", (_req, res) =>
  res.json({ ok: true, ts: new Date().toISOString() })
);

// Emitir NFS-e
app.post("/nfse/emitir", async (req, res) => {
  if (!checkAuth(req, res)) return;
  try {
    const { cpf, senha, ambiente = "producao", dps } = req.body;
    if (!cpf || !senha || !dps)
      return res.status(400).json({ ok: false, error: "cpf, senha e dps obrigatórios" });

    const token = await autenticar(cpf, senha, ambiente);
    const url = URLS[ambiente].dps;

    const emitirRes = await fetch(url, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(dps)
    });

    const resultado = await emitirRes.json();
    if (!emitirRes.ok)
      return res.status(400).json({ ok: false, error: JSON.stringify(resultado) });

    res.json({ ok: true, dados: resultado });
  } catch (e) {
    console.error("[nfse/emitir]", e);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Cancelar NFS-e
app.post("/nfse/cancelar", async (req, res) => {
  if (!checkAuth(req, res)) return;
  try {
    const { cpf, senha, ambiente = "producao", chave_nfse, motivo } = req.body;
    if (!cpf || !senha || !chave_nfse || !motivo)
      return res.status(400).json({ ok: false, error: "campos obrigatórios faltando" });

    const token = await autenticar(cpf, senha, ambiente);
    const cancelRes = await fetch(
      `${URLS[ambiente].dps}/cancel`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ chNFSe: chave_nfse, xJust: motivo })
      }
    );

    const resultado = await cancelRes.json();
    res.json({ ok: cancelRes.ok, dados: resultado });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Consultar NFS-e
app.get("/nfse/consultar/:chave", async (req, res) => {
  if (!checkAuth(req, res)) return;
  try {
    const { cpf, senha, ambiente = "producao" } = req.query;
    const { chave } = req.params;

    const token = await autenticar(cpf, senha, ambiente);
    const consultaRes = await fetch(
      `${URLS[ambiente].dps}/${chave}`,
      { headers: { "Authorization": `Bearer ${token}` } }
    );

    const resultado = await consultaRes.json();
    res.json({ ok: consultaRes.ok, dados: resultado });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`[nfse-proxy] rodando na porta ${PORT}`)
);
