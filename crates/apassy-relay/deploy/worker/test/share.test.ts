// The viewer of public links (connect-share-v1 section 5): public/share.js opens the contract
// vectors with WebCrypto, refuses a changed binding, asks before a one-time link, takes the
// fragment out of the address bar before its first request, and makes no request to another
// origin; the Worker serves the page at /s with its headers. Run with: node --test test/
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import worker from "../src/index.ts";

interface LinkVector {
  name: string;
  key_b64u: string;
  link: string;
  link_id: string;
  address_key_b64u: string;
  expires_at: number;
  one_time: boolean;
  access: "anyone" | "emails";
  snapshot: { title: string; items: { title: string; fields: { name: string; value: string; secret: boolean }[] }[] };
  associated_data_b64u: string;
  sealed_b64u: string;
  addresses: { input: string; normalized: string; hash: string }[];
}

interface Viewer {
  keyFromFragment(fragment: string): Uint8Array | null;
  deriveLink(key: Uint8Array): Promise<{ linkId: string; sealKey: unknown; addressKey: string }>;
  associatedData(origin: string, linkId: string, expiresAt: number, oneTime: boolean, access: string): Uint8Array;
  openSealed(sealKey: unknown, sealed: string, associated: Uint8Array): Promise<LinkVector["snapshot"] | null>;
  toB64u(bytes: Uint8Array): string;
  start(env: unknown): Promise<void>;
}

const viewer = (await import(new URL("../public/share.js", import.meta.url).href)) as Viewer;
const vectors = JSON.parse(
  readFileSync(new URL("../../../../../tests/fixtures/connect-share-v1/link-vectors.json", import.meta.url), "utf8"),
) as { origin: string; links: LinkVector[] };
const ORIGIN = vectors.origin;
const anyone = vectors.links.find((link) => link.name === "anyone")!;
const onceByMail = vectors.links.find((link) => link.name === "one_time_emails")!;
const HTML = readFileSync(new URL("../public/share.html", import.meta.url), "utf8");
const SCRIPT = readFileSync(new URL("../public/share.js", import.meta.url), "utf8");

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

type Answer = { status: number; body: unknown };

function ok(result: unknown): Answer {
  return { status: 200, body: { ok: true, result } };
}

function refused(status: number, code: string): Answer {
  return { status, body: { ok: false, error: { code, message: code } } };
}

function page(hash: string, answer: (call: Call, index: number) => Answer, now = (anyone.expires_at - 3600) * 1000) {
  const root = new FakeElement("main");
  const calls: Call[] = [];
  const replaced: { url: string; callsBefore: number; hashBefore: string }[] = [];
  const copied: string[] = [];
  const location = { hash, origin: ORIGIN, pathname: "/s" };
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
      const { status, body } = answer(call, calls.length - 1);
      return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    },
    document: {
      title: "",
      getElementById: (id: string) => (id === "app" ? root : null),
      createElement: (tag: string) => new FakeElement(tag),
      createTextNode: (data: string) => new FakeText(data),
    },
    clipboard: {
      async writeText(value: string) {
        copied.push(value);
      },
    },
    now: () => now,
  };
  const done = viewer.start(env);
  return { root, calls, replaced, copied, location, done };
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

function sealedAnswer(link: LinkVector, change: Partial<{ expires_at: number; one_time: boolean; access: string }> = {}) {
  return ok({ expires_at: link.expires_at, one_time: link.one_time, access: link.access, sealed: link.sealed_b64u, ...change });
}

const GONE = "This link does not open";

// ---------------------------------------------------------------------------

describe("the viewer of public links", () => {
  it("derives the link id and the address key of each vector", async () => {
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
    await until(() => view.root.textContent.includes("synthetic-Pa55-0001") || view.root.find("data-item") !== undefined, "the item");
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
    const reveal = view.root.find("data-action", "reveal")!;
    await reveal.fire("click");
    assert.ok(view.root.textContent.includes("synthetic-Pa55-0001"));
    const copies = view.root.all().filter((element) => element.attributes.get("data-action") === "copy");
    await copies[2]!.fire("click");
    assert.deepEqual(view.copied, ["synthetic-Pa55-0001"]);
  });

  it("a changed expiry fails", async () => {
    for (const change of [{ expires_at: anyone.expires_at + 1 }, { expires_at: anyone.expires_at - 1 }, { one_time: true }, { access: "emails" }]) {
      const view = page(fragment(anyone), () => sealedAnswer(anyone, change));
      await until(() => view.root.textContent.includes(GONE), "the refusal");
      assert.ok(!view.root.textContent.includes("db.staging.example"), JSON.stringify(change));
    }
    // A link at another origin does not open either.
    const key = viewer.keyFromFragment(fragment(anyone))!;
    const derived = await viewer.deriveLink(key);
    const elsewhere = viewer.associatedData("https://relay.example", anyone.link_id, anyone.expires_at, false, "anyone");
    assert.equal(await viewer.openSealed(derived.sealKey, anyone.sealed_b64u, elsewhere), null);
  });

  it("refuses a snapshot whose expiry has passed by the reader's clock", async () => {
    const view = page(fragment(anyone), () => sealedAnswer(anyone), anyone.expires_at * 1000);
    await until(() => view.root.textContent.includes(GONE), "the refusal");
  });

  it("gives one answer for every link that does not open", async () => {
    for (const answer of [refused(404, "not_found"), { status: 404, body: "not json" }]) {
      const view = page(fragment(anyone), () => answer);
      await until(() => view.root.textContent.includes(GONE), "the refusal");
      assert.ok(view.root.textContent.includes("expired, been revoked, or been opened already"));
    }
  });

  it("a one-time link asks first", async () => {
    const link = { ...anyone, one_time: true };
    const view = page(fragment(anyone), (call) =>
      ok({ expires_at: link.expires_at, one_time: true, access: "anyone", sealed: call.body.confirm === true ? "AAAA" : null }),
    );
    await until(() => view.root.find("data-action", "open") !== undefined, "the question");
    assert.equal(view.calls.length, 1);
    assert.equal(view.calls[0]!.body.confirm, false);
    assert.ok(view.root.textContent.includes("shows its content once"));
    await view.root.find("data-action", "open")!.fire("click");
    await until(() => view.calls.length === 2, "the second request");
    assert.equal(view.calls[1]!.body.confirm, true);
  });

  it("opens a one-time link of some addresses with the code", async () => {
    const [ada] = onceByMail.addresses;
    const view = page(
      fragment(onceByMail),
      (call) => {
        if (call.path.endsWith("/code")) return ok({ expires_in: 600 });
        const withCode = call.body.code === "123456" && call.body.confirm === true;
        if (call.body.code !== null && !withCode) return refused(403, "code_invalid");
        return ok({
          expires_at: onceByMail.expires_at,
          one_time: true,
          access: "emails",
          sealed: withCode ? onceByMail.sealed_b64u : null,
        });
      },
      (onceByMail.expires_at - 60) * 1000,
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
    view.root.find("data-input", "code")!.value = "654321";
    await view.root.find("data-form", "code")!.fire("submit");
    await until(() => view.root.find("data-note") !== undefined, "the wrong code note");
    view.root.find("data-input", "code")!.value = "123 456";
    await view.root.find("data-form", "code")!.fire("submit");
    await until(() => view.root.textContent.includes("Router"), "the items");
    const last = view.calls.at(-1)!;
    assert.deepEqual(last.body, { confirm: true, email: ada!.input.trim(), address_key: onceByMail.address_key_b64u, code: "123456" });
    assert.ok(view.root.textContent.includes("Home Wi-Fi"));
    assert.ok(view.root.textContent.includes("Devices"));
    assert.ok(view.root.textContent.includes("used up"));
  });

  it("refuses a sealed form of an e-mail link without a code", async () => {
    const view = page(fragment(onceByMail), () => sealedAnswer(onceByMail, { one_time: false }), (onceByMail.expires_at - 60) * 1000);
    await until(() => view.root.textContent.includes(GONE), "the refusal");
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

  it("loads only its own files and writes the snapshot as text", () => {
    assert.match(HTML, /<script type="module" src="\/share\.js"><\/script>/);
    assert.match(HTML, /<link rel="stylesheet" href="\/share\.css">/);
    assert.equal((HTML.match(/<script/g) ?? []).length, 1, "no inline script");
    assert.ok(!/<style|\sstyle=|\son[a-z]+=/i.test(HTML), "no inline style or event attribute");
    assert.ok(!/https?:\/\//.test(HTML), "no other origin");
    for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage", "sessionStorage", "document.cookie", "http://", "https://", "import("]) {
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
        assert.equal(
          response.headers.get("content-security-policy"),
          "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        );
        assert.equal(response.headers.get("cache-control"), "no-store");
        assert.equal(response.headers.get("referrer-policy"), "no-referrer");
        assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow");
        assert.equal(response.headers.get("x-content-type-options"), "nosniff");
        assert.equal(response.headers.get("x-frame-options"), "DENY");
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
