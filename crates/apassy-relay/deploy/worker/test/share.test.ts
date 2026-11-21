// The viewer of public links (connect-share-v1 section 5): public/share.js opens the contract
// vectors with WebCrypto, refuses a changed binding at the AEAD, asks before a one-time link and
// shows it after the yes, takes the fragment out of the address bar before its first request,
// keeps a fixed title, and makes no request to another origin; the Worker serves the page at /s
// with its headers, refuses service-worker scripts, and sandboxes the agent proxy (section 5.1).
// Run with: node --test test/
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import worker from "../src/index.ts";

interface Snapshot {
  v: number;
  title: string;
  items: { title: string; kind: string; path: string[]; fields: { name: string; value: string; secret: boolean }[]; notes: string }[];
}

interface LinkVector {
  name: string;
  key_b64u: string;
  link: string;
  link_id: string;
  address_key_b64u: string;
  expires_at: number;
  one_time: boolean;
  access: "anyone" | "emails";
  snapshot: Snapshot;
  associated_data_b64u: string;
  sealed_b64u: string;
  addresses: { input: string; normalized: string; hash: string }[];
}

interface Viewer {
  keyFromFragment(fragment: string): Uint8Array | null;
  deriveLink(key: Uint8Array): Promise<{ linkId: string; sealKey: unknown; addressKey: string }>;
  associatedData(origin: string, linkId: string, expiresAt: number, oneTime: boolean, access: string): Uint8Array;
  openSealed(sealKey: unknown, sealed: string, associated: Uint8Array): Promise<Snapshot | null>;
  toB64u(bytes: Uint8Array): string;
  start(env: unknown): Promise<void>;
}

const viewer = (await import(new URL("../public/share.js", import.meta.url).href)) as Viewer;
const vectors = JSON.parse(
  readFileSync(new URL("../../../../../tests/fixtures/connect-share-v1/link-vectors.json", import.meta.url), "utf8"),
) as { origin: string; links: LinkVector[] };
const ORIGIN = vectors.origin;
const byName = (name: string) => vectors.links.find((link) => link.name === name)!;
const anyone = byName("anyone");
const onceAnyone = byName("one_time_anyone");
const onceByMail = byName("one_time_emails");
const HTML = readFileSync(new URL("../public/share.html", import.meta.url), "utf8");
const SCRIPT = readFileSync(new URL("../public/share.js", import.meta.url), "utf8");
const CSP =
  "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

// ---------------------------------------------------------------------------
// A fake page: only the DOM calls that share.js makes.
// ---------------------------------------------------------------------------

class FakeText {
  data: string;
  constructor(data: string) {
    this.data = data;
  }
  get textContent(): string {
    return this.data;
  }
}

type Listener = (event: { preventDefault(): void }) => unknown;

class FakeElement {
  tagName: string;
  children: (FakeElement | FakeText)[] = [];
  attributes = new Map<string, string>();
  listeners = new Map<string, Listener[]>();
  value = "";
  disabled = false;
  constructor(tag: string) {
    this.tagName = tag.toLowerCase();
  }
  setAttribute(name: string, value: string) {
    this.attributes.set(name, String(value));
  }
  append(...nodes: (FakeElement | FakeText)[]) {
    this.children.push(...nodes);
  }
  replaceChildren(...nodes: (FakeElement | FakeText)[]) {
    this.children = [...nodes];
  }
  addEventListener(type: string, listener: Listener) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }
  focus() {}
  get textContent(): string {
    return this.children.map((child) => child.textContent).join("");
  }
  set textContent(value: string) {
    this.children = [new FakeText(String(value))];
  }
  all(): FakeElement[] {
    return this.children.flatMap((child) => (child instanceof FakeElement ? [child, ...child.all()] : []));
  }
  find(attribute: string, value?: string): FakeElement | undefined {
    return this.all().find((element) => element.attributes.has(attribute) && (value === undefined || element.attributes.get(attribute) === value));
  }
  async fire(type: string) {
    for (const listener of this.listeners.get(type) ?? []) await listener({ preventDefault() {} });
  }
}

/** What the viewer passes to fetch; workers-types does not name the two browser fields. */
type ViewerInit = RequestInit & { credentials?: string; referrerPolicy?: string };

interface Call {
  path: string;
  body: Record<string, unknown>;
  init: ViewerInit;
}

/** An answer of the fake server, or "network" for a fetch that fails. */
type Answer = { status: number; body: unknown } | "network";

function ok(result: unknown): Answer {
  return { status: 200, body: { ok: true, result } };
}

function refused(status: number, code: string): Answer {
  return { status, body: { ok: false, error: { code, message: code } } };
}

interface PageOptions {
  now?: number;
  crypto?: unknown;
}

function page(hash: string, answer: (call: Call, index: number) => Answer, options: PageOptions = {}) {
  const now = options.now ?? (anyone.expires_at - 3600) * 1000;
  const root = new FakeElement("main");
  const calls: Call[] = [];
  const replaced: { url: string; callsBefore: number; hashBefore: string }[] = [];
  const copied: string[] = [];
  const location = { hash, origin: ORIGIN, pathname: "/s" };
  const document = {
    title: "Shared with Apassy",
    getElementById: (id: string) => (id === "app" ? root : null),
    createElement: (tag: string) => new FakeElement(tag),
    createTextNode: (data: string) => new FakeText(data),
  };
  const env = {
    location,
    history: {
      replaceState(_state: unknown, _title: string, url: string) {
        replaced.push({ url, callsBefore: calls.length, hashBefore: location.hash });
        location.hash = "";
      },
    },
    async fetch(path: string, init: ViewerInit) {
      const call = { path, init, body: JSON.parse(String(init.body)) as Record<string, unknown> };
      calls.push(call);
      const reply = answer(call, calls.length - 1);
      if (reply === "network") throw new TypeError("fetch failed");
      return new Response(typeof reply.body === "string" ? reply.body : JSON.stringify(reply.body), {
        status: reply.status,
        headers: { "content-type": "application/json" },
      });
    },
    document,
    clipboard: {
      async writeText(value: string) {
        copied.push(value);
      },
    },
    now: () => now,
    ...(options.crypto === undefined ? {} : { crypto: options.crypto }),
  };
  const done = viewer.start(env);
  return { root, calls, replaced, copied, location, document, done };
}

/** Waits until the page shows what `ready` looks for: WebCrypto runs off the main thread. */
async function until(ready: () => boolean, what: string) {
  for (let tries = 0; tries < 400; tries++) {
    if (ready()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail(`the page never showed ${what}`);
}

function fragment(link: LinkVector): string {
  return "#v1." + link.key_b64u;
}

type Meta = { expires_at: number; one_time: boolean; access: string };

function sealedAnswer(link: LinkVector, change: Partial<Meta> = {}) {
  return ok({ expires_at: link.expires_at, one_time: link.one_time, access: link.access, sealed: link.sealed_b64u, ...change });
}

/** Counts the AES-GCM opens of the page and how many of them failed. */
function spyDecrypt() {
  const subtle = crypto.subtle as unknown as { decrypt: (...args: unknown[]) => Promise<ArrayBuffer> };
  const original = subtle.decrypt;
  const counts = { calls: 0, failures: 0 };
  subtle.decrypt = async (...args: unknown[]) => {
    counts.calls++;
    try {
      return await original.apply(crypto.subtle, args);
    } catch (error) {
      counts.failures++;
      throw error;
    }
  };
  return { counts, restore: () => void (subtle.decrypt = original) };
}

/** Seals a snapshot as a device would (contract section 3), with a new key: the fragment. */
async function sealLink(snapshot: Snapshot, meta: Meta): Promise<{ hash: string; sealed: string }> {
  const encoder = new TextEncoder();
  const key = crypto.getRandomValues(new Uint8Array(32));
  const base = await crypto.subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
  const bits = async (info: string, length: number) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(info) },
        base,
        length * 8,
      ),
    );
  const linkId = Buffer.from(await bits("apassy-connect public-link id v1", 16)).toString("hex");
  const sealKey = await crypto.subtle.importKey("raw", await bits("apassy-connect public-link key v1", 32), "AES-GCM", false, ["encrypt"]);
  const json = encoder.encode(JSON.stringify(snapshot));
  const padded = new Uint8Array(Math.ceil(json.length / 1024) * 1024).fill(0x20);
  padded.set(json);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const associated = viewer.associatedData(ORIGIN, linkId, meta.expires_at, meta.one_time, meta.access);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: associated }, sealKey, padded),
  );
  return { hash: "#v1." + viewer.toB64u(key), sealed: viewer.toB64u(new Uint8Array([...nonce, ...ciphertext])) };
}

const GONE = "This link does not open";

// ---------------------------------------------------------------------------

describe("the viewer of public links", () => {
  it("derives the link id and the address key of each vector", async () => {
    assert.equal(vectors.links.length, 3);
    for (const link of vectors.links) {
      assert.equal(link.link, `${ORIGIN}/s#v1.${link.key_b64u}`);
      const key = viewer.keyFromFragment(fragment(link))!;
      assert.equal(key.length, 32);
      const derived = await viewer.deriveLink(key);
      assert.equal(derived.linkId, link.link_id);
      assert.equal(derived.addressKey, link.address_key_b64u);
      const associated = viewer.associatedData(ORIGIN, link.link_id, link.expires_at, link.one_time, link.access);
      assert.equal(viewer.toB64u(associated), link.associated_data_b64u);
      assert.deepEqual(await viewer.openSealed(derived.sealKey, link.sealed_b64u, associated), link.snapshot);
    }
    for (const bad of ["", "#", "#v1.", "#v2." + anyone.key_b64u, "#v1." + anyone.key_b64u + "A", "#v1." + anyone.key_b64u.slice(0, -1) + "B"]) {
      assert.equal(viewer.keyFromFragment(bad), null, bad);
    }
  });

  it("the viewer opens the contract vector", async () => {
    const view = page(fragment(anyone), () => sealedAnswer(anyone));
    await until(() => view.root.find("data-item") !== undefined, "the item");
    assert.equal(view.calls.length, 1, "one request");
    const [call] = view.calls;
    assert.equal(call!.path, `/v1/links/${anyone.link_id}/open`);
    assert.deepEqual(call!.body, { confirm: false, email: null, address_key: null, code: null });
    assert.equal(call!.init.method, "POST");
    assert.equal(call!.init.credentials, "omit");
    assert.equal(call!.init.referrerPolicy, "no-referrer");
    const text = view.root.textContent;
    assert.ok(text.includes("Staging database"));
    assert.ok(text.includes("db.staging.example"));
    assert.ok(!text.includes("synthetic-Pa55-0001"), "a secret value stays hidden");
    await view.root.find("data-action", "reveal")!.fire("click");
    assert.ok(view.root.textContent.includes("synthetic-Pa55-0001"));
    const copies = view.root.all().filter((element) => element.attributes.get("data-action") === "copy");
    await copies[2]!.fire("click");
    assert.deepEqual(view.copied, ["synthetic-Pa55-0001"]);
    assert.equal(view.document.title, "Shared with Apassy", "the title never names the secret");
  });

  it("a changed expiry fails", async () => {
    // Each change passes every check of the page and fails at the AES-GCM open.
    const spy = spyDecrypt();
    try {
      for (const [link, change] of [
        [anyone, { expires_at: anyone.expires_at + 1 }],
        [anyone, { expires_at: anyone.expires_at - 1 }],
        [anyone, { one_time: true }],
        [onceAnyone, { one_time: false }],
        [onceByMail, { access: "anyone" }],
      ] as [LinkVector, Partial<Meta>][]) {
        const before = { ...spy.counts };
        const view = page(fragment(link), () => sealedAnswer(link, change), { now: (link.expires_at - 3600) * 1000 });
        await until(() => view.root.textContent.includes(GONE), "the refusal");
        assert.equal(spy.counts.calls - before.calls, 1, JSON.stringify(change));
        assert.equal(spy.counts.failures - before.failures, 1, JSON.stringify(change));
        assert.equal(view.root.find("data-item"), undefined);
      }
      // An `anyone` link that Connect answers as `emails`: through the code, then the AEAD.
      const before = { ...spy.counts };
      const view = page(fragment(anyone), (call) => {
        if (call.path.endsWith("/code")) return ok({ expires_in: 900 });
        return ok({ expires_at: anyone.expires_at, one_time: false, access: "emails", sealed: call.body.code === null ? null : anyone.sealed_b64u });
      });
      await until(() => view.root.find("data-form", "email") !== undefined, "the address form");
      view.root.find("data-input", "email")!.value = "ada.lovelace@example.com";
      await view.root.find("data-form", "email")!.fire("submit");
      await until(() => view.root.find("data-form", "code") !== undefined, "the code form");
      view.root.find("data-input", "code")!.value = "12345678";
      await view.root.find("data-form", "code")!.fire("submit");
      await until(() => view.root.textContent.includes(GONE), "the refusal");
      assert.equal(spy.counts.failures - before.failures, 1);
    } finally {
      spy.restore();
    }
    // A link at another origin does not open either.
    const derived = await viewer.deriveLink(viewer.keyFromFragment(fragment(anyone))!);
    const elsewhere = viewer.associatedData("https://relay.example", anyone.link_id, anyone.expires_at, false, "anyone");
    assert.equal(await viewer.openSealed(derived.sealKey, anyone.sealed_b64u, elsewhere), null);
  });

  it("refuses a snapshot whose expiry has passed by the reader's clock", async () => {
    const view = page(fragment(anyone), () => sealedAnswer(anyone), { now: anyone.expires_at * 1000 });
    await until(() => view.root.textContent.includes(GONE), "the refusal");
  });

  it("gives one answer for every link that does not open", async () => {
    for (const answer of [refused(404, "not_found"), { status: 404, body: "not json" }] as Answer[]) {
      const view = page(fragment(anyone), () => answer);
      await until(() => view.root.textContent.includes(GONE), "the refusal");
      assert.ok(view.root.textContent.includes("expired, been revoked, or been opened already"));
      assert.equal(view.root.find("data-action", "retry"), undefined);
    }
  });

  it("a one-time link asks first", async () => {
    const view = page(
      fragment(onceAnyone),
      (call) => sealedAnswer(onceAnyone, call.body.confirm === true ? {} : ({ sealed: null } as never)),
      { now: (onceAnyone.expires_at - 3600) * 1000 },
    );
    await until(() => view.root.find("data-action", "open") !== undefined, "the question");
    assert.equal(view.calls.length, 1);
    assert.equal(view.calls[0]!.body.confirm, false);
    assert.ok(view.root.textContent.includes("shows its content once"));
    assert.ok(!view.root.textContent.includes("Deploy token"), "nothing shows before the yes");
    await view.root.find("data-action", "open")!.fire("click");
    await until(() => view.root.find("data-item") !== undefined, "the content after the yes");
    assert.equal(view.calls.length, 2);
    assert.equal(view.calls[1]!.body.confirm, true);
    assert.ok(view.root.textContent.includes("Deploy token"));
    assert.ok(view.root.textContent.includes("used up"));
    await view.root.find("data-action", "reveal")!.fire("click");
    assert.ok(view.root.textContent.includes("synthetic-token-0004"));
  });

  it("opens a one-time link of some addresses with the code", async () => {
    const [ada] = onceByMail.addresses;
    const view = page(
      fragment(onceByMail),
      (call) => {
        if (call.path.endsWith("/code")) return ok({ expires_in: 900 });
        const withCode = call.body.code === "12345678" && call.body.confirm === true;
        if (call.body.code !== null && !withCode) return refused(403, "code_invalid");
        return ok({ expires_at: onceByMail.expires_at, one_time: true, access: "emails", sealed: withCode ? onceByMail.sealed_b64u : null });
      },
      { now: (onceByMail.expires_at - 60) * 1000 },
    );
    await until(() => view.root.find("data-form", "email") !== undefined, "the address form");
    assert.equal(view.calls.length, 1);
    view.root.find("data-input", "email")!.value = ada!.input;
    await view.root.find("data-form", "email")!.fire("submit");
    await until(() => view.root.find("data-form", "code") !== undefined, "the code form");
    const codeCall = view.calls[1]!;
    assert.equal(codeCall.path, `/v1/links/${onceByMail.link_id}/code`);
    assert.deepEqual(codeCall.body, { email: ada!.input.trim(), address_key: onceByMail.address_key_b64u });
    assert.ok(view.root.textContent.includes("shows its content once"));
    assert.ok(view.root.textContent.includes("8 digits"));
    // A code of 6 digits is not sent at all.
    view.root.find("data-input", "code")!.value = "123456";
    await view.root.find("data-form", "code")!.fire("submit");
    assert.equal(view.calls.length, 2);
    view.root.find("data-input", "code")!.value = "87654321";
    await view.root.find("data-form", "code")!.fire("submit");
    await until(() => view.root.find("data-note") !== undefined, "the wrong code note");
    view.root.find("data-input", "code")!.value = "1234 5678";
    await view.root.find("data-form", "code")!.fire("submit");
    await until(() => view.root.textContent.includes("Router"), "the items");
    assert.deepEqual(view.calls.at(-1)!.body, { confirm: true, email: ada!.input.trim(), address_key: onceByMail.address_key_b64u, code: "12345678" });
    assert.ok(view.root.textContent.includes("Home Wi-Fi"));
    assert.ok(view.root.textContent.includes("Devices"));
    assert.ok(view.root.textContent.includes("used up"));
  });

  it("gives a 400 and a 503 mail_unavailable their own texts, and Try Again only where it can help", async () => {
    const emails = (code: Answer) => (call: Call) =>
      call.path.endsWith("/code") ? code : ok({ expires_at: onceByMail.expires_at, one_time: true, access: "emails", sealed: null });
    const send = async (answer: Answer) => {
      const view = page(fragment(onceByMail), emails(answer), { now: (onceByMail.expires_at - 60) * 1000 });
      await until(() => view.root.find("data-form", "email") !== undefined, "the address form");
      view.root.find("data-input", "email")!.value = "ada.lovelace@example.com";
      await view.root.find("data-form", "email")!.fire("submit");
      return view;
    };
    const mail = await send(refused(503, "mail_unavailable"));
    await until(() => mail.root.textContent.includes("cannot send codes now"), "the mail text");
    assert.equal(mail.root.find("data-action", "retry"), undefined);
    const invalid = await send(refused(400, "invalid_request"));
    await until(() => invalid.root.find("data-note") !== undefined, "the address note");
    assert.ok(invalid.root.textContent.includes("not an e-mail address"));
    const down = await send({ status: 502, body: "relay unreachable" });
    await until(() => down.root.find("data-action", "retry") !== undefined, "Try Again");
    const offline = page(fragment(anyone), () => "network");
    await until(() => offline.root.find("data-action", "retry") !== undefined, "Try Again");
    const refusedOpen = page(fragment(anyone), () => refused(400, "invalid_request"));
    await until(() => refusedOpen.root.textContent.includes("does not open here"), "the refusal");
    assert.equal(refusedOpen.root.find("data-action", "retry"), undefined);
  });

  it("names an unknown kind as an item, also one of Object's own names", async () => {
    const meta = { expires_at: anyone.expires_at, one_time: false, access: "anyone" };
    const snapshot: Snapshot = {
      v: 1,
      title: "Odd kinds",
      items: ["constructor", "__proto__", "toString", "login"].map((kind) => ({
        title: "Kind " + kind,
        kind,
        path: [],
        fields: [],
        notes: "",
      })),
    };
    const link = await sealLink(snapshot, meta);
    const view = page(link.hash, () => ok({ ...meta, sealed: link.sealed }));
    await until(() => view.root.find("data-item") !== undefined, "the items");
    const labels = view.root.all().filter((element) => element.attributes.get("class") === "muted").map((element) => element.textContent);
    assert.deepEqual(labels.slice(1), ["Item", "Item", "Item", "Login"]);
  });

  it("says that a link opens only over HTTPS without WebCrypto, and sends nothing", async () => {
    const view = page(fragment(anyone), () => sealedAnswer(anyone), { crypto: {} });
    await view.done;
    assert.equal(view.calls.length, 0);
    assert.equal(view.location.hash, "");
    assert.ok(view.root.textContent.includes("only over HTTPS"));
  });

  it("the fragment leaves the address bar", async () => {
    const view = page(fragment(anyone), () => sealedAnswer(anyone));
    await until(() => view.calls.length === 1, "the request");
    assert.deepEqual(view.replaced, [{ url: "/s", callsBefore: 0, hashBefore: fragment(anyone) }]);
    assert.equal(view.location.hash, "");
    const incomplete = page("#v1.short", () => sealedAnswer(anyone));
    await incomplete.done;
    assert.equal(incomplete.calls.length, 0);
    assert.equal(incomplete.location.hash, "");
    assert.ok(incomplete.root.textContent.includes("not complete"));
  });

  it("loads only its own files, keeps a fixed title, and writes the snapshot as text", () => {
    assert.match(HTML, /<script type="module" src="\/share\.js"><\/script>/);
    assert.match(HTML, /<link rel="stylesheet" href="\/share\.css">/);
    assert.match(HTML, /<title>Shared with Apassy<\/title>/);
    assert.equal((HTML.match(/<script/g) ?? []).length, 1, "no inline script");
    assert.ok(!/<style|\sstyle=|\son[a-z]+=/i.test(HTML), "no inline style or event attribute");
    assert.ok(!/https?:\/\//.test(HTML), "no other origin");
    for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage", "sessionStorage", "document.cookie", "document.title =", "http://", "https://", "import(", "serviceWorker"]) {
      assert.ok(!SCRIPT.includes(forbidden), forbidden);
    }
  });
});

describe("the Worker serves the viewer", () => {
  function assets() {
    const requests: Request[] = [];
    return {
      requests,
      binding: {
        async fetch(request: Request) {
          requests.push(request);
          const path = new URL(request.url).pathname;
          const type = path.endsWith(".js") ? "text/javascript" : path.endsWith(".css") ? "text/css" : "text/html";
          return new Response(request.method === "HEAD" ? null : "asset " + path, {
            headers: { "content-type": type, "cache-control": "public, max-age=3600" },
          });
        },
      },
    };
  }

  const env = (binding: unknown) => ({ ASSETS: binding, RELAY_ORIGIN: "http://127.0.0.1:9", EDGE_SECRET: "edge-secret-synthetic" });

  for (const [path, asset] of [["/s", "/share.html"], ["/share.js", "/share.js"], ["/share.css", "/share.css"]]) {
    it(`serves ${path} with the viewer headers`, async () => {
      const fixture = assets();
      for (const mode of ["relay", "connect"]) {
        const response = await worker.fetch(new Request(`${ORIGIN}${path}?x=1`), { ...env(fixture.binding), RELAY_MODE: mode } as never);
        assert.equal(response.status, 200);
        assert.equal(await response.text(), "asset " + asset);
        assert.equal(response.headers.get("content-security-policy"), CSP);
        assert.equal(response.headers.get("cache-control"), "no-store");
        assert.equal(response.headers.get("referrer-policy"), "no-referrer");
        assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow");
        assert.equal(response.headers.get("x-content-type-options"), "nosniff");
        assert.equal(response.headers.get("x-frame-options"), "DENY");
        assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
        assert.equal(response.headers.get("location"), null, "no redirect");
      }
      const request = fixture.requests[0]!;
      assert.equal(new URL(request.url).pathname, asset);
      assert.equal(new URL(request.url).search, "");
      assert.equal(request.headers.get("x-apassy-edge"), null);
    });
  }

  it("refuses another method on /s with the viewer headers", async () => {
    const fixture = assets();
    const response = await worker.fetch(new Request(`${ORIGIN}/s`, { method: "POST", body: "x" }), env(fixture.binding) as never);
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
    assert.equal(fixture.requests.length, 0);
  });

  it("serves no other asset by its own name", async () => {
    const fixture = assets();
    let relayed = 0;
    const relay = { async fetch() { relayed++; return new Response("relay", { status: 404 }); } };
    const response = await worker.fetch(new Request(`${ORIGIN}/share.html`), { ...env(fixture.binding), RELAY: relay } as never);
    assert.equal(response.status, 404);
    assert.equal(fixture.requests.length, 0);
    assert.equal(relayed, 1);
  });
});

describe("no other script of the origin (connect-share-v1 section 5.1)", () => {
  it("refuses a service-worker script on every path, before the assets and the relay", async () => {
    let assetCalls = 0;
    let relayed = 0;
    const assetsBinding = { async fetch() { assetCalls++; return new Response("asset"); } };
    const relay = { async fetch() { relayed++; return new Response("relay"); } };
    for (const mode of ["relay", "connect"]) {
      for (const path of ["/s", "/share.js", "/p/agent/x.js", "/v1/links/" + anyone.link_id + "/open", "/guide", "/dl/x", "/internal/push", "/sw.js"]) {
        for (const value of ["script", " Script "]) {
          const request = new Request(ORIGIN + path, { headers: { "service-worker": value } });
          const response = await worker.fetch(request, { ASSETS: assetsBinding, RELAY: relay, EDGE_SECRET: "edge-secret-synthetic", RELAY_MODE: mode } as never);
          assert.equal(response.status, 400, `${mode} ${path}`);
          const body = (await response.json()) as { error: { code: string } };
          assert.equal(body.error.code, "invalid_request");
        }
      }
    }
    assert.equal(assetCalls, 0);
    assert.equal(relayed, 0);
  });

  it("sandboxes the answers of the agent proxy and drops Service-Worker-Allowed", async () => {
    const relay = {
      async fetch() {
        return new Response("<script>1</script>", {
          status: 200,
          headers: { "content-type": "text/html", "service-worker-allowed": "/", "content-security-policy": "default-src *", "x-upstream": "kept" },
        });
      },
    };
    const response = await worker.fetch(new Request(ORIGIN + "/p/agent/page"), { RELAY: relay, EDGE_SECRET: "edge-secret-synthetic" } as never);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "<script>1</script>");
    assert.equal(response.headers.get("service-worker-allowed"), null);
    assert.equal(response.headers.get("content-security-policy"), "default-src *, sandbox");
    assert.equal(response.headers.get("x-upstream"), "kept");
    // Another route of the relay keeps its answer as it is.
    const other = await worker.fetch(new Request(ORIGIN + "/v1/links/" + anyone.link_id + "/open", { method: "POST", body: "{}", headers: { "content-length": "2" } }), { RELAY: relay, EDGE_SECRET: "edge-secret-synthetic" } as never);
    assert.equal(other.headers.get("service-worker-allowed"), "/");
    assert.equal(other.headers.get("content-security-policy"), "default-src *");
  });
});
