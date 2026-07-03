const PAYLOAD_URL = "secure/payload.json";

let loadSequence = 0;
let objectUrls = [];

function $(selector) {
  return document.querySelector(selector);
}

function status(message) {
  const node = $("#statusText");
  if (node) node.textContent = message;
}

function setBusy(busy) {
  const button = $("#accessForm button");
  const input = $("#accessToken");
  if (button) button.disabled = busy;
  if (input) input.disabled = busy;
}

function supportsReservedAccess() {
  return Boolean(
    window.isSecureContext &&
      window.crypto?.subtle &&
      window.TextEncoder &&
      window.TextDecoder &&
      window.atob &&
      window.Blob &&
      window.URL?.createObjectURL
  );
}

function extractAccessToken() {
  const raw = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
  const params = new URLSearchParams(raw);
  return params.get("acesso") || params.get("access") || "";
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToText(bytes) {
  return new TextDecoder().decode(bytes);
}

function replaceAllLiteral(input, from, to) {
  return input.split(from).join(to);
}

function replaceAssetReferences(text, urls) {
  let output = text;
  for (const [file, url] of urls.entries()) {
    output = replaceAllLiteral(output, file, url);
  }
  return output;
}

function rememberObjectUrl(url) {
  objectUrls.push(url);
  return url;
}

function revokeObjectUrls() {
  for (const url of objectUrls) URL.revokeObjectURL(url);
  objectUrls = [];
}

async function deriveKey(token, payload) {
  const passphrase = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(token.trim()),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64ToBytes(payload.kdf.salt),
      iterations: payload.kdf.iterations,
      hash: payload.kdf.hash,
    },
    passphrase,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptPackage(token, payload) {
  const key = await deriveKey(token, payload);
  const encryptedData = await loadEncryptedData(payload);
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
    key,
    encryptedData
  );
  return JSON.parse(bytesToText(new Uint8Array(clear)));
}

async function loadEncryptedData(payload) {
  if (payload.data) return base64ToBytes(payload.data);
  if (!Array.isArray(payload.chunks) || payload.chunks.length === 0) {
    throw new Error("Payload incompleto.");
  }

  const parts = await Promise.all(
    payload.chunks.map((chunk) =>
      fetch(chunk, { cache: "no-store" }).then((response) => {
        if (!response.ok) throw new Error("Payload indisponível.");
        return response.text();
      })
    )
  );
  return base64ToBytes(parts.join(""));
}

async function waitForFrameLoad(frame, url) {
  await new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      reject(new Error("Tempo esgotado ao carregar conteúdo."));
    }, 15000);

    frame.onload = () => {
      window.clearTimeout(timeout);
      resolve();
    };
    frame.onerror = () => {
      window.clearTimeout(timeout);
      reject(new Error("Falha ao carregar conteúdo."));
    };
    frame.src = url;
  });
}

async function loadDemo(rawToken) {
  const token = rawToken.trim();
  if (!supportsReservedAccess()) {
    status("Este navegador não suporta a abertura segura. Use Chrome, Edge ou Safari atualizados.");
    return;
  }

  if (!token) {
    status("Use o link completo recebido ou cole o código de acesso.");
    return;
  }

  const sequence = ++loadSequence;
  setBusy(true);
  status("Desbloqueando...");

  try {
    const payload = await fetch(PAYLOAD_URL, { cache: "no-store" }).then((response) => {
      if (!response.ok) throw new Error("Payload indisponível.");
      return response.json();
    });
    const pack = await decryptPackage(token, payload);
    if (sequence !== loadSequence) return;

    revokeObjectUrls();

    const files = new Map(
      pack.files.map((entry) => [entry.path, { entry, clear: base64ToBytes(entry.data) }])
    );
    const urls = new Map();

    for (const [file, fileData] of files.entries()) {
      if (file.endsWith(".html") || file.endsWith(".css")) continue;
      const blob = new Blob([fileData.clear], { type: fileData.entry.mime });
      urls.set(file, rememberObjectUrl(URL.createObjectURL(blob)));
    }

    const cssFile = files.get("styles.css");
    if (cssFile) {
      const css = replaceAssetReferences(bytesToText(cssFile.clear), urls);
      urls.set(
        "styles.css",
        rememberObjectUrl(URL.createObjectURL(new Blob([css], { type: cssFile.entry.mime })))
      );
    }

    const htmlFile = files.get("index.html");
    if (!htmlFile) throw new Error("HTML não encontrado.");
    let html = bytesToText(htmlFile.clear);
    html = replaceAssetReferences(html, urls);
    const htmlUrl = rememberObjectUrl(URL.createObjectURL(new Blob([html], { type: htmlFile.entry.mime })));

    const frame = $("#demoFrame");
    await waitForFrameLoad(frame, htmlUrl);
    if (sequence !== loadSequence) return;

    $("#viewer").hidden = false;
    document.body.classList.add("unlocked");
    status("Conteúdo aberto.");
    const input = $("#accessToken");
    if (input) input.value = "";
    history.replaceState(null, "", `${window.location.pathname}${window.location.search}#inicio`);
  } catch (error) {
    console.error(error);
    status("Código inválido ou payload indisponível. Confira o link recebido.");
  } finally {
    setBusy(false);
  }
}

function loadFromHash() {
  const token = extractAccessToken();
  if (token) loadDemo(token);
}

document.addEventListener("DOMContentLoaded", () => {
  if (!supportsReservedAccess()) {
    status("Este navegador não suporta a abertura segura. Use Chrome, Edge ou Safari atualizados.");
    return;
  }

  loadFromHash();

  $("#accessForm")?.addEventListener("submit", (event) => {
    event.preventDefault();
    loadDemo($("#accessToken")?.value || "");
  });
});

window.addEventListener("hashchange", loadFromHash);
