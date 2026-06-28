const express = require("express");
const https = require("https");
const forge = require("node-forge");
const { SignedXml } = require("xml-crypto");
const { create } = require("xmlbuilder2");
const zlib = require("zlib");

const app = express();
app.use(express.json({ limit: "10mb" }));

const URLS = {
  producao:    { host: "sefin.nfse.gov.br",                  path: "/SefinNacional/nfse" },
  homologacao: { host: "sefin.producaorestrita.nfse.gov.br", path: "/SefinNacional/nfse" }
};

function carregarCertificadoBase64(pfxBase64, senha) {
  if (!pfxBase64) throw new Error("pfx_base64 nao enviado");
  const pfxData = Buffer.from(pfxBase64, "base64");
  const p12 = forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(pfxData.toString("binary")), senha);
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];
  const certPem = forge.pki.certificateToPem(certBags[0].cert);
  const chainPem = certBags.map(b => forge.pki.certificateToPem(b.cert)).join("\n");
  const keyPem = forge.pki.privateKeyToPem(keyBags[0].key);
  return { certPem, keyPem, chainPem };
}

function httpsPost(host, urlPath, body, certPem, keyPem, chainPem) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const options = {
      hostname: host, port: 443, path: urlPath, method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(bodyStr) },
      cert: certPem, key: keyPem, ca: chainPem, rejectUnauthorized: false, minVersion: "TLSv1.2", servername: host
    };
    const req = https.request(options, (res) => {
      let data = ""; res.on("data", c => data += c); res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject); req.write(bodyStr); req.end();
  });
}

function httpsGet(host, urlPath, certPem, keyPem, chainPem) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: host, port: 443, path: urlPath, method: "GET",
      cert: certPem, key: keyPem, ca: chainPem, rejectUnauthorized: false, minVersion: "TLSv1.2", servername: host
    };
    const req = https.request(options, (res) => {
      let data = ""; res.on("data", c => data += c); res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject); req.end();
  });
}

function montarDpsXml(d) {
  const cLocEmiStr = String(d.cLocEmi).padStart(7, "0");
  const docLimpo = String(d.cnpj).replace(/\D/g, "");
  const isCnpj = docLimpo.length === 14;
  const tpInsc = isCnpj ? "2" : "1";
  const tagDoc = isCnpj ? "CNPJ" : "CPF";
  const docPadId = docLimpo.padStart(14, "0");
  const serieStr = String(d.serie).padStart(5, "0");
  const nDPSStr = String(d.nDPS).padStart(15, "0");
  const id = "DPS" + cLocEmiStr + tpInsc + docPadId + serieStr + nDPSStr;

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
      // tpEmit=1 (prestador = emitente): NAO enviar <xNome> (E0121) nem <end> (E0128).
      .ele("prest")
        .ele(tagDoc).txt(docLimpo).up()
        .ele("IM").txt(String(d.im)).up()
        .ele("fone").txt(String(d.prest?.fone || "32999999999")).up()
        .ele("email").txt(d.prest?.email || "teste@teste.com").up()
        .ele("regTrib")
          .ele("opSimpNac").txt(String(d.prest?.regTrib?.opSimpNac ?? 1)).up()
          .ele("regEspTrib").txt(String(d.prest?.regTrib?.regEspTrib ?? 0)).up()
        .up()
      .up();

  if (d.tomador) {
    const t = root.ele("toma");
    if (d.tomador.cpf) t.ele("CPF").txt(d.tomador.cpf.replace(/\D/g, "")).up();
    else if (d.tomador.cnpj) t.ele("CNPJ").txt(d.tomador.cnpj.replace(/\D/g, "")).up();
    if (d.tomador.nome) t.ele("xNome").txt(d.tomador.nome).up();
    t.up();
  }

  root.ele("serv")
      .ele("locPrest").ele("cLocPrestacao").txt(String(d.cLocIncid)).up().up()
      .ele("cServ").ele("cTribNac").txt(d.cTribNac).up().ele("xDescServ").txt(d.xDescServ).up().up()
    .up();

  root.ele("valores")
        .ele("vServPrest").ele("vServ").txt(parseFloat(d.vServ).toFixed(2)).up().up()
        .ele("trib")
          .ele("tribMun")
            .ele("tribISSQN").txt("1").up()
            .ele("tpRetISSQN").txt("1").up()
          .up()
          .ele("totTrib").ele("indTotTrib").txt(String(d.indTotTrib || "0")).up().up()
        .up()
      .up();

  return { xml: root.end({ prettyPrint: false }), id };
}

function assinarXml(xmlStr, id, keyPem, certPem) {
  const certBase64 = certPem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/[\r\n]/g, "");

  const sig = new SignedXml({
    privateKey: keyPem,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });

  sig.addReference({
    xpath: `//*[@Id='${id}']`,
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    uri: `#${id}`,
  });

  sig.getKeyInfoContent = () =>
    `<X509Data><X509Certificate>${certBase64}</X509Certificate></X509Data>`;

  sig.computeSignature(xmlStr, {
    prefix: "",
    location: { reference: `//*[local-name(.)='infDPS']`, action: "after" },
  });

  return sig.getSignedXml();
}

const comprimirBase64 = (xmlStr) => zlib.gzipSync(Buffer.from(xmlStr, "utf-8")).toString("base64");

app.get("/health", (_req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

app.post("/nfse/testar", async (req, res) => {
  try {
    const { cnpj, senha_cert, pfx_base64, ambiente = "homologacao" } = req.body;
    if (!cnpj || !senha_cert || !pfx_base64) return res.status(400).json({ ok: false, error: "cnpj, senha_cert e pfx_base64 obrigatorios" });
    const { certPem, keyPem, chainPem } = carregarCertificadoBase64(pfx_base64, senha_cert);
    const url = URLS[ambiente];
    const r = await httpsGet(url.host, url.path, certPem, keyPem, chainPem);
    res.json({ ok: true, status: r.status, mensagem: "Certificado valido" });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/nfse/emitir", async (req, res) => {
  try {
    const { cnpj, senha_cert, pfx_base64, ambiente = "producao", dps, prest, tomador } = req.body;
    if (!cnpj || !senha_cert || !pfx_base64 || !dps) return res.status(400).json({ ok: false, error: "campos obrigatorios (cnpj, senha_cert, pfx_base64, dps)" });
    const { certPem, keyPem, chainPem } = carregarCertificadoBase64(pfx_base64, senha_cert);
    const { xml: xmlStr, id } = montarDpsXml({ cnpj, ...dps, prest, tomador: tomador || dps.tomador });
    const xmlAssinado = assinarXml(xmlStr, id, keyPem, certPem);
    const payload = comprimirBase64(xmlAssinado);
    const url = URLS[ambiente] || URLS.producao;
    const r = await httpsPost(url.host, url.path, { dpsXmlGZipB64: payload }, certPem, keyPem, chainPem);
    let resultado; try { resultado = JSON.parse(r.body); } catch (e) { resultado = r.body; }
    if (r.status >= 400) return res.status(400).json({ ok: false, error: JSON.stringify(resultado) });
    res.json({ ok: true, dados: resultado });
  } catch (e) { console.error(e); res.status(500).json({ ok: false, error: e.message }); }
});

app.post("/nfse/cancelar", async (req, res) => {
  try {
    const { cnpj, senha_cert, pfx_base64, ambiente = "producao", chave_nfse, motivo } = req.body;
    if (!cnpj || !senha_cert || !pfx_base64 || !chave_nfse || !motivo) return res.status(400).json({ ok: false, error: "campos obrigatorios" });
    const { certPem, keyPem, chainPem } = carregarCertificadoBase64(pfx_base64, senha_cert);
    const url = URLS[ambiente] || URLS.producao;
    const r = await httpsPost(url.host, url.path + "/" + chave_nfse + "/eventos", { xJust: motivo }, certPem, keyPem, chainPem);
    let resultado; try { resultado = JSON.parse(r.body); } catch (e) { resultado = r.body; }
    res.json({ ok: r.status < 400, dados: resultado });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, "0.0.0.0", () => console.log("[nfse-proxy] porta " + PORT));
