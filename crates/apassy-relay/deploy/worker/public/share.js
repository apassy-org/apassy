// The viewer of an Apassy public link (docs/contracts/connect-share-v1.md section 5).
//
// It reads the key from the fragment of `<origin>/s#v1.<key>`, takes the fragment out of the
// address bar, asks its own origin for the sealed form, and opens it with WebCrypto. No
// dependency, no build step, no request to another origin, no storage. Every text of the
// snapshot is written as text, never as markup.
//
// The functions above `start` are pure and exported for the tests
// (deploy/worker/test/share.test.ts), which run this module in Node with a fake page.

export const TAG_ID = "apassy-connect public-link id v1";
export const TAG_KEY = "apassy-connect public-link key v1";
export const TAG_ADDRESS = "apassy-connect public-link address v1";
export const TAG_SEAL = "apassy-connect public-link v1";
const PAD = 1024;
const MAX_PLAINTEXT = 32 * 1024;
const KINDS = { api_key: "API key", login: "Login", ssh_key: "SSH key", database: "Database", custom: "Item" };

const encoder = new TextEncoder();

/** b64u without padding to bytes, or null for any text that is not its canonical form. */
export function fromB64u(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const base = text.replace(/-/g, "+").replace(/_/g, "/");
  let binary;
  try {
    binary = atob(base + "===".slice((base.length + 3) % 4));
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return toB64u(bytes) === text ? bytes : null;
}

export function toB64u(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The 32-byte key of a fragment `#v1.<key>`, or null. */
export function keyFromFragment(fragment) {
  const match = /^#v1\.([A-Za-z0-9_-]{43})$/.exec(fragment ?? "");
  if (!match) return null;
  const key = fromB64u(match[1]);
  return key && key.length === 32 ? key : null;
}

async function hkdf(key, info, length) {
  const base = await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** The link id (hex), the seal key (a WebCrypto key), and the address key (b64u) of a link key. */
export async function deriveLink(key) {
  const linkId = toHex(await hkdf(key, TAG_ID, 16));
  const sealBytes = await hkdf(key, TAG_KEY, 32);
  const sealKey = await crypto.subtle.importKey("raw", sealBytes, "AES-GCM", false, ["decrypt"]);
  sealBytes.fill(0);
  const addressBytes = await hkdf(key, TAG_ADDRESS, 32);
  const addressKey = toB64u(addressBytes);
  addressBytes.fill(0);
  return { linkId, sealKey, addressKey };
}

/** The associated data of contract section 3. */
export function associatedData(origin, linkId, expiresAt, oneTime, access) {
  return encoder.encode([TAG_SEAL, origin, linkId, String(expiresAt), oneTime ? "1" : "0", access].join("\0"));
}

function text(value, max) {
  return typeof value === "string" && encoder.encode(value).length <= max;
}

function validSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || snapshot.v !== 1) return false;
  if (!text(snapshot.title, 128) || !Array.isArray(snapshot.items)) return false;
  if (snapshot.items.length < 1 || snapshot.items.length > 100) return false;
  return snapshot.items.every(
    (item) =>
      item &&
      text(item.title, 128) &&
      typeof item.kind === "string" &&
      Array.isArray(item.path) &&
      item.path.every((name) => text(name, 64)) &&
      Array.isArray(item.fields) &&
      item.fields.length <= 64 &&
      item.fields.every((field) => field && text(field.name, 64) && typeof field.value === "string" && typeof field.secret === "boolean") &&
      typeof item.notes === "string",
  );
}

/** Opens a sealed form (b64u) with the seal key and the associated data: the snapshot, or null. */
export async function openSealed(sealKey, sealed, associated) {
  const bytes = fromB64u(sealed);
  if (!bytes || bytes.length < 12 + PAD + 16 || bytes.length > 12 + MAX_PLAINTEXT + 16) return null;
  let plain;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: bytes.subarray(0, 12), additionalData: associated, tagLength: 128 },
        sealKey,
        bytes.subarray(12),
      ),
    );
  } catch {
    return null;
  }
  if (plain.length % PAD !== 0) return null;
  try {
    const snapshot = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain));
    return validSnapshot(snapshot) ? snapshot : null;
  } catch {
    return null;
  } finally {
    plain.fill(0);
  }
}

function validResult(result) {
  return (
    result &&
    Number.isSafeInteger(result.expires_at) &&
    typeof result.one_time === "boolean" &&
    (result.access === "anyone" || result.access === "emails") &&
    (result.sealed === null || typeof result.sealed === "string")
  );
}

// ---------------------------------------------------------------------------
// The page. `env` holds what the page uses of the browser, so a test can give a fake one:
// `location` (`hash`, `origin`, `pathname`), `history` (`replaceState`), `fetch`, `document`,
// `clipboard` (optional), `now` (milliseconds), and `window` (optional, for `hashchange`).
// ---------------------------------------------------------------------------

export function start(env) {
  const { document } = env;
  const root = document.getElementById("app");
  const now = env.now ?? (() => Date.now());

  function h(tag, attributes, ...children) {
    const element = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes ?? {})) element.setAttribute(name, value);
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      element.append(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return element;
  }

  function show(...children) {
    root.replaceChildren(...children.filter(Boolean));
  }

  function message(title, body, action) {
    show(h("h1", null, title), h("p", null, body), action);
  }

  function gone() {
    message(
      "This link does not open",
      "It may have expired, been revoked, or been opened already. Ask the person who sent it for a new link.",
    );
  }

  function failed(retry) {
    const button = h("button", { type: "button", "data-action": "retry" }, "Try Again");
    button.addEventListener("click", retry);
    message("Apassy cannot reach the server", "Check your connection and try again.", button);
  }

  function limited() {
    message("Too many tries", "Wait a minute, then try again.");
  }

  async function post(path, body) {
    let response;
    try {
      response = await env.fetch(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch {
      return { kind: "network" };
    }
    let envelope = null;
    try {
      envelope = await response.json();
    } catch {
      // Not JSON: the server or the edge failed.
    }
    if (response.status === 404) return { kind: "gone" };
    if (response.status === 429) return { kind: "limited" };
    if (response.status === 403 && envelope?.error?.code === "code_invalid") return { kind: "code_invalid" };
    if (response.status === 400) return { kind: "invalid" };
    if (!response.ok || envelope?.ok !== true) return { kind: "network" };
    return { kind: "ok", result: envelope.result };
  }

  async function run() {
    const key = keyFromFragment(env.location.hash);
    // The key leaves the address bar before the first request, so it is not in the history
    // entry, a bookmark, or a screen share of the address bar.
    if (env.location.hash) env.history.replaceState(null, "", env.location.pathname || "/s");
    if (!key) {
      message("This link is not complete", "Copy the whole link, with the part after #, and open it again.");
      return;
    }
    show(h("p", { "data-state": "loading" }, "Opening…"));
    const link = await deriveLink(key);
    key.fill(0);
    await open(link, { confirm: false, email: null, address_key: null, code: null });
  }

  async function open(link, body) {
    const answer = await post(`/v1/links/${link.linkId}/open`, body);
    if (answer.kind === "gone") return gone();
    if (answer.kind === "limited") return limited();
    if (answer.kind === "code_invalid") {
      return askCode(link, body.email, "The code is not right, or it ended. Check it, or send a new code.", link.meta);
    }
    if (answer.kind !== "ok" || !validResult(answer.result)) return failed(() => open(link, body));
    const result = answer.result;
    link.meta = result;
    const withCode = body.code !== null;
    if (result.sealed === null) {
      if (result.access === "emails" && !withCode) return askAddress(link, result);
      if (result.one_time && !body.confirm) return confirmOnce(link, result);
      return gone();
    }
    // A sealed form of an `emails` link comes only after a code.
    if (result.access === "emails" && !withCode) return gone();
    if (result.expires_at * 1000 <= now()) return gone();
    const associated = associatedData(env.location.origin, link.linkId, result.expires_at, result.one_time, result.access);
    const snapshot = await openSealed(link.sealKey, result.sealed, associated);
    if (!snapshot) return gone();
    content(snapshot, result);
  }

  function confirmOnce(link, result) {
    const button = h("button", { type: "button", "data-action": "open" }, "Open Now");
    button.addEventListener("click", () => {
      button.disabled = true;
      open(link, { confirm: true, email: null, address_key: null, code: null });
    });
    show(
      h("h1", null, "This link shows its content once"),
      h("p", null, "After you open it, nobody can open it again, also not you. Open it when you can keep what you need."),
      h("p", { class: "muted" }, `The link ends ${when(result.expires_at)}.`),
      button,
    );
  }

  function askAddress(link, result, note) {
    const input = h("input", { type: "email", name: "email", autocomplete: "email", required: "", "data-input": "email" });
    const form = h(
      "form",
      { "data-form": "email" },
      h("label", null, "E-mail address", input),
      h("button", { type: "submit", "data-action": "send-code" }, "Send Code"),
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const email = String(input.value ?? "").trim();
      if (!email) return;
      const answer = await post(`/v1/links/${link.linkId}/code`, { email, address_key: link.addressKey });
      if (answer.kind === "gone") return gone();
      if (answer.kind === "limited") return limited();
      if (answer.kind === "invalid") return askAddress(link, result, "This is not an e-mail address. Check it.");
      if (answer.kind !== "ok") return failed(() => askAddress(link, result));
      askCode(link, email, null, result);
    });
    show(
      h("h1", null, "Only some people can open this link"),
      h("p", null, "Type your e-mail address. If it may open this link, Apassy sends a code to it."),
      note ? h("p", { class: "note", "data-note": "" }, note) : null,
      form,
    );
    input.focus?.();
  }

  function askCode(link, email, note, result) {
    const oneTime = result?.one_time ?? false;
    const input = h("input", { type: "text", name: "code", inputmode: "numeric", autocomplete: "one-time-code", required: "", "data-input": "code" });
    const form = h(
      "form",
      { "data-form": "code" },
      h("label", null, "Code", input),
      h("button", { type: "submit", "data-action": "open" }, oneTime ? "Open Now" : "Open"),
    );
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const code = String(input.value ?? "").replace(/\s+/g, "");
      if (!/^[0-9]{6}$/.test(code)) return;
      open(link, { confirm: true, email, address_key: link.addressKey, code });
    });
    const again = h("button", { type: "button", class: "secondary", "data-action": "new-code" }, "Send a New Code");
    again.addEventListener("click", () => askAddress(link, result ?? { one_time: false }));
    show(
      h("h1", null, "Check your mail"),
      h("p", null, `If ${email} may open this link, a code is on its way. It works for 10 minutes.`),
      oneTime ? h("p", null, "This link shows its content once. After you open it, nobody can open it again.") : null,
      note ? h("p", { class: "note", "data-note": "" }, note) : null,
      form,
      again,
    );
    input.focus?.();
  }

  function when(seconds) {
    return new Date(seconds * 1000).toLocaleString();
  }

  function field(entry) {
    const value = h("span", { class: entry.secret ? "value secret" : "value" }, entry.secret ? "••••••••" : entry.value);
    const buttons = [];
    if (entry.secret) {
      const toggle = h("button", { type: "button", class: "small", "data-action": "reveal" }, "Show");
      let shown = false;
      toggle.addEventListener("click", () => {
        shown = !shown;
        value.textContent = shown ? entry.value : "••••••••";
        toggle.textContent = shown ? "Hide" : "Show";
      });
      buttons.push(toggle);
    }
    if (env.clipboard) {
      const copy = h("button", { type: "button", class: "small", "data-action": "copy" }, "Copy");
      copy.addEventListener("click", async () => {
        try {
          await env.clipboard.writeText(entry.value);
          copy.textContent = "Copied";
        } catch {
          copy.textContent = "Copy failed";
        }
      });
      buttons.push(copy);
    }
    return h("div", { class: "field" }, h("span", { class: "name" }, entry.name), value, ...buttons);
  }

  function content(snapshot, result) {
    if (document.title !== undefined) document.title = `${snapshot.title} · Apassy`;
    const items = snapshot.items.map((item) =>
      h(
        "section",
        { class: "item", "data-item": "" },
        h("h2", null, item.title),
        h(
          "p",
          { class: "muted" },
          [KINDS[item.kind] ?? "Item", ...(item.path.length ? [item.path.join(" › ")] : [])].join(" · "),
        ),
        ...item.fields.map((entry) => field(entry)),
        item.notes ? h("p", { class: "notes" }, item.notes) : null,
      ),
    );
    show(
      h("h1", null, snapshot.title),
      h(
        "p",
        { class: "muted" },
        result.one_time
          ? "This link is now used up. Keep what you need before you close this page."
          : `Shared with Apassy. The link ends ${when(result.expires_at)}.`,
      ),
      ...items,
    );
  }

  env.window?.addEventListener?.("hashchange", () => {
    if (env.location.hash) run();
  });
  return run();
}

if (typeof document !== "undefined" && typeof window !== "undefined" && document.getElementById("app")) {
  start({
    location: window.location,
    history: window.history,
    fetch: (...args) => window.fetch(...args),
    document,
    clipboard: navigator.clipboard,
    window,
  });
}
