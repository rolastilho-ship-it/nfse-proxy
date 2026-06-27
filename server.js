const express = require("express");
const https = require("https");
const fs = require("fs");
const path = require("path");
const forge = require("node-forge");
const { SignedXml } = require("xml-crypto");
const { create } = require("xmlbuilder2");
const zlib = require("zlib");

const app = express();
app.use(express.json({ limit: "10mb" }));
const CERT_DIR = path.join(__dirname, "certificados");
const URLS = {
  producao: { host: "www.nfse.gov.br", path: "/SefinNacional/nfse" },
  homologacao: { host: "sefin.producaorestrita.nfse.gov.br", path: "/API/SefinNacional/nfse" }
};

function carregarCertificado(cnpj, senha) {
  const cnpjDigits = cnpj.replace(/\D/g, "");
  const arquivos = fs.readdirSync(CERT_DIR);
  const arquivo = arquivos.find(f => f.includes(cnpjDigits) && f.endsWith(".pfx"));
  if (!arquivo) throw new Error("Certificado nao encontrado para CNPJ " + cnpjDigits);
  const pfxData = fs.readFileSync(path.join(CERT_DIR, arquivo));
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxData.toString("binary")), senha);
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
  const certPem = forge.pki.certificateToPem(certBags[0].cert);
  const chainPem = certBags.map(b => forge.pki.certificateToPem(b.cert)).join("\n");
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);
  return { certPem, keyPem, pfxData, chainPem };
}

function httpsPost(host, urlPath, body, pfxData, senha, certPem, keyPem, chainPem) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const options = {
      hostname: host, port: 443, path: urlPath, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(bodyStr) },
      cert: certPem, key: keyPem, ca: chainPem, rejectUnauthorized: false, minVersion: "TLSv1.2", servername: host
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.write(bodyStr);
    req.end();
  });
}

function httpsGet(host, urlPath, pfxData, senha, certPem, keyPem, chainPem) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: host, port: 443, path: urlPath, method: "GET",
      cert: certPem, key: keyPem, ca: chainPem, rejectUnauthorized: false, minVersion: "TLSv1.2", servername: host
    };
    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.end();
  });
}

function montarDpsXml(d) {
  const cLocEmiStr = String(d.cLocEmi).padStart(7,"0");
  const tpInsc = String(d.cnpj).replace(/\D/g,"").length === 14 ? "2" : "1";
  const docStr = String(d.cnpj).replace(/\D/g,"").padStart(14,"0");
  const serieStr = String(d.serie).padStart(5,"0");
  const nDPSStr = String(d.nDPS).padStart(15,"0");
  const id = "DPS" + cLocEmiStr + tpInsc + docStr + serieStr + nDPSStr;
  const root = create({ version: "1.0", encoding: "UTF-8" })
    .ele("DPS", { xmlns: "http://www.sped.fazenda.gov.br/nfse", versao: "1.00" })
    .ele("infDPS", { Id: id })
      .ele("tpAmb").txt(String(d.tpAmb)).up()
      .ele("dhEmi").txt(d.dhEmi).up()
      .ele("verAplic").txt("NFSeProxy-1.0").up()
      .ele("serie").txt(String(d.serie)).up()
      .ele("nDPS").txt(String(d.nDPS)).up()
      .ele("dCompet").txt(d.dCompet).up()
      .ele("tpEmit").txt("1").up()
      .ele("cLocEmi").txt(String(d.cLocEmi)).up()
      .ele("prest")
        .ele("CNPJ").txt(String(d.cnpj).replace(/\D/g,"")).up()
        .ele("IM").txt(String(d.im)).up()
        .ele("xNome").txt(d.prest?.xNome || "EMPRESA TESTE").up()
        .ele("end")
          .ele("endNac").ele("cMun").txt(String(d.prest?.end?.cMun || d.cLocEmi)).up().ele("CEP").txt(String(d.prest?.end?.CEP || "36320000")).up().up()
          .ele("xLgr").txt(d.prest?.end?.xLgr || "RUA TESTE").up()
          .ele("nro").txt(String(d.prest?.end?.nro || "100")).up()
          .ele("xBairro").txt(d.prest?.end?.xBairro || "CENTRO").up()
        .up()
        .ele("fone").txt(String(d.prest?.fone || "32999999999")).up()
        .ele("email").txt(d.prest?.email || "teste@teste.com").up()
        .ele("regTrib")
          .ele("opSimpNac").txt(String(d.prest?.regTrib?.opSimpNac ?? 1)).up()
          .ele("regEspTrib").txt(String(d.prest?.regTrib?.regEspTrib ?? 0)).up()
        .up()
      .up();
  if (d.tomador) {
    const t = root.ele("toma");
    if (d.tomador.cpf) t.ele("CPF").txt(d.tomador.cpf.replace(/\D/g,"")).up();
    else if (d.tomador.cnpj) t.ele("CNPJ").txt(d.tomador.cnpj.replace(/\D/g,"")).up();
    if (d.tomador.nome) t.ele("xNome").txt(d.tomador.nome).up();
    t.up();
  }
  root.ele("serv")
      .ele("locPrest")
        .ele("cLocPrestacao").txt(String(d.cLocIncid)).up()
      .up()
      .ele("cServ")
        .ele("cTribNac").txt(d.cTribNac).up()
        .ele("xDescServ").txt(d.xDescServ).up()
      .up()
    .up();
  root.ele("valores").ele("vServPrest").ele("vServ").txt(parseFloat(d.vServ).toFixed(2)).up().up().ele("trib").ele("tribMun").ele("tribISSQN").txt("1").up().ele("tpRetISSQN").txt("1").up().up().ele("totTrib").ele("indTotTrib").txt(String(d.indTotTrib||"0")).up().up().up().up();
  return root.end({ prettyPrint: false });
}

function assinarXml(xmlStr, keyPem, certPem) {
  const certBase64 = certPem.replace("-----BEGIN CERTIFICATE-----","").replace("-----END CERTIFICATE-----","").replace(/\n/g,"");
  const sig = new SignedXml({ privateKey: keyPem });
  sig.addReference({ xpath: "//*[local-name(.)='infDPS']", transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
  sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
  sig.signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
  sig.keyInfoProvider = { getKeyInfo: () => "<X509Data><X509Certificate>" + certBase64 + "</X509Certificate></X509Data>" };
  sig.computeSignature(xmlStr);
  return sig.getSignedXml();
}

function comprimirBase64(xmlStr) {
  return zlib.gzipSync(Buffer.from(xmlStr,"utf-8")).toString("base64");
}

app.get("/health", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.post("/nfse/testar", async (req, res) => {
  try {
    const { cnpj, senha_cert, ambiente = "homologacao" } = req.body;
    if (!cnpj || !senha_cert) return res.status(400).json({ ok: false, error: "cnpj e senha_cert obrigatorios" });
    const { certPem, keyPem, pfxData, chainPem } = carregarCertificado(cnpj, senha_cert);
    const url = URLS[ambiente];
    const r = await httpsGet(url.host, url.path, pfxData, senha_cert, certPem, keyPem, chainPem);
    res.json({ ok: true, status: r.status, mensagem: "Certificado valido" });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/nfse/emitir", async (req, res) => {
  try {
    const { cnpj, senha_cert, ambiente = "producao", dps, prest, tomador } = req.body;
    if (!cnpj || !senha_cert || !dps) return res.status(400).json({ ok: false, error: "campos obrigatorios" });
    const { certPem, keyPem, pfxData, chainPem } = carregarCertificado(cnpj, senha_cert);
    const xmlStr = montarDpsXml({ cnpj, ...dps, prest, tomador: tomador || dps.tomador });
    const xmlAssinado = assinarXml(xmlStr, keyPem, certPem);
    console.log("[emitir] XML assinado:", xmlAssinado);
    const payload = comprimirBase64(xmlAssinado);
    const url = URLS[ambiente] || URLS.producao;
    console.log("[emitir] enviando para", url.host + url.path);
    const r = await httpsPost(url.host, url.path, { dpsXmlGZipB64: payload }, pfxData, senha_cert, certPem, keyPem, chainPem);
    console.log("[emitir] status:", r.status, "resp:", r.body.substring(0,300));
    let resultado; try { resultado = JSON.parse(r.body); } catch(e) { resultado = r.body; }
    if (r.status >= 400) return res.status(400).json({ ok: false, error: JSON.stringify(resultado) });
    res.json({ ok: true, dados: resultado });
  } catch(e) { console.error(e); res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/nfse/cancelar", async (req, res) => {
  try {
    const { cnpj, senha_cert, ambiente = "producao", chave_nfse, motivo } = req.body;
    if (!cnpj || !senha_cert || !chave_nfse || !motivo) return res.status(400).json({ ok: false, error: "campos obrigatorios" });
    const { certPem, keyPem, pfxData, chainPem } = carregarCertificado(cnpj, senha_cert);
    const url = URLS[ambiente] || URLS.producao;
    const r = await httpsPost(url.host, url.path + "/" + chave_nfse + "/eventos", { xJust: motivo }, pfxData, senha_cert, certPem, keyPem, chainPem);
    let resultado; try { resultado = JSON.parse(r.body); } catch(e) { resultado = r.body; }
    res.json({ ok: r.status < 400, dados: resultado });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, "0.0.0.0", () => console.log("[nfse-proxy] porta " + PORT));
