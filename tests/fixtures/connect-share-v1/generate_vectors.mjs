// Makes tests/fixtures/connect-share-v1/link-vectors.json (docs/contracts/connect-share-v1.md
// section 9): two public links with every derived value, the exact padded plaintext, the
// associated data and the sealed form, and the address normalisation and hash vectors.
// Synthetic keys and values only.
//
// Run from the repository root with Node 22 or later (WebCrypto, no package):
//
//     node tests/fixtures/connect-share-v1/generate_vectors.mjs
//
// The output is deterministic: the link keys and nonces are fixed, so a new run gives the
// same file. For the address normal form the Rust implementation (`idna::domain_to_ascii`,
// `connect_share_v1::normalize` in tests/contracts.rs) is the reference (contract section 6):
// the WHATWG URL parser here gives the same results for every case below, and the Rust test
// fails if one of them differs. tests/contracts.rs checks it with `ring`, and the viewer test
// (crates/apassy-relay/deploy/worker/test/share.test.ts) opens it with WebCrypto.

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "link-vectors.json");
const ORIGIN = "https://apassy-relay.wyderka.cc";
const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

const TAG_ID = "apassy-connect public-link id v1";
const TAG_KEY = "apassy-connect public-link key v1";
const TAG_ADDRESS = "apassy-connect public-link address v1";
const TAG_SEAL = "apassy-connect public-link v1";
const PAD = 1024;

function b64u(bytes) {
  return Buffer.from(bytes).toString("base64url");
}
function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}
/** 32 or 12 synthetic bytes, from the SHA-256 of a label. */
function fixed(label, length) {
  return new Uint8Array(createHash("sha256").update(label).digest()).slice(0, length);
}
function joined(parts) {
  return encoder.encode(parts.join("\0"));
}
async function hkdf(key, info, length) {
  const base = await subtle.importKey("raw", key, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}
async function hmac(key, data) {
  const imported = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", imported, data));
}

/** Section 6: the normal form of an address, or null when the text is not an address. */
export function normalizeAddress(text) {
  const trimmed = text.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
  const parts = trimmed.split("@");
  if (parts.length !== 2) return null;
  const [local, rawDomain] = parts;
  if (!/^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~.]{1,64}$/.test(local)) return null;
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) return null;
  // ASCII is limited to letters, digits, dots and hyphens before the IDNA step.
  if (rawDomain === "" || /[\u0000-,/:-@[-`{-\u007f]/.test(rawDomain)) return null;
  let domain;
  try {
    domain = new URL("http://" + rawDomain + "/").hostname;
  } catch {
    return null;
  }
  // One trailing dot goes after the ASCII step, so a mapped full-width dot counts too.
  if (domain.endsWith(".")) domain = domain.slice(0, -1);
  const labels = domain.split(".");
  if (domain.length > 253 || labels.length < 2) return null;
  if (!labels.every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null;
  if (!/^[a-z]/.test(labels[labels.length - 1])) return null;
  const address = local.toLowerCase() + "@" + domain;
  return address.length <= 254 ? address : null;
}

async function link(spec) {
  const key = fixed("connect-share-v1 link key " + spec.name, 32);
  const nonce = fixed("connect-share-v1 nonce " + spec.name, 12);
  const linkId = hex(await hkdf(key, TAG_ID, 16));
  const sealKey = await hkdf(key, TAG_KEY, 32);
  const addressKey = await hkdf(key, TAG_ADDRESS, 32);
  const json = encoder.encode(JSON.stringify(spec.snapshot));
  const padded = new Uint8Array(Math.ceil(json.length / PAD) * PAD).fill(0x20);
  padded.set(json);
  const associated = joined([TAG_SEAL, ORIGIN, linkId, String(spec.expires_at), spec.one_time ? "1" : "0", spec.access]);
  const aes = await subtle.importKey("raw", sealKey, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: associated, tagLength: 128 }, aes, padded),
  );
  const sealed = new Uint8Array(nonce.length + ciphertext.length);
  sealed.set(nonce);
  sealed.set(ciphertext, nonce.length);
  const addresses = [];
  for (const input of spec.addresses) {
    const normalized = normalizeAddress(input);
    if (normalized === null) throw new Error("not an address: " + input);
    addresses.push({ input, normalized, hash: b64u(await hmac(addressKey, encoder.encode(normalized))) });
  }
  return {
    name: spec.name,
    key_b64u: b64u(key),
    link: ORIGIN + "/s#v1." + b64u(key),
    link_id: linkId,
    seal_key_hex: hex(sealKey),
    address_key_b64u: b64u(addressKey),
    expires_at: spec.expires_at,
    one_time: spec.one_time,
    access: spec.access,
    snapshot: spec.snapshot,
    json_length: json.length,
    plaintext_b64u: b64u(padded),
    associated_data_b64u: b64u(associated),
    nonce_hex: hex(nonce),
    sealed_b64u: b64u(sealed),
    addresses,
    // The body of POST /v1/account/links (section 4.1) for this link.
    create: {
      link_id: linkId,
      sealed: b64u(sealed),
      expires_at: spec.expires_at,
      one_time: spec.one_time,
      access: spec.access,
      address_hashes: addresses.map((address) => address.hash),
    },
  };
}

const links = [
  await link({
    name: "anyone",
    expires_at: 1764331200,
    one_time: false,
    access: "anyone",
    addresses: [],
    snapshot: {
      v: 1,
      title: "Staging database",
      items: [
        {
          title: "Staging database",
          kind: "database",
          path: [],
          fields: [
            { name: "Host", value: "db.staging.example", secret: false },
            { name: "User", value: "app", secret: false },
            { name: "Password", value: "synthetic-Pa55-0001", secret: true },
          ],
          notes: "Synthetic vector. Not a real credential.",
        },
      ],
    },
  }),
  await link({
    name: "one_time_anyone",
    expires_at: 1764334800,
    one_time: true,
    access: "anyone",
    addresses: [],
    snapshot: {
      v: 1,
      title: "Deploy token",
      items: [
        {
          title: "Deploy token",
          kind: "api_key",
          path: [],
          fields: [{ name: "Token", value: "synthetic-token-0004", secret: true }],
          notes: "",
        },
      ],
    },
  }),
  await link({
    name: "one_time_emails",
    expires_at: 1764331800,
    one_time: true,
    access: "emails",
    addresses: [" Ada.Lovelace@Example.COM ", "grace@BÜCHER.example"],
    snapshot: {
      v: 1,
      title: "Family › Wi-Fi",
      items: [
        {
          title: "Home Wi-Fi",
          kind: "login",
          path: [],
          fields: [
            { name: "Network", value: "synthetic-net", secret: false },
            { name: "Password", value: "zażółć-gęślą-0002", secret: true },
          ],
          notes: "",
        },
        {
          title: "Router",
          kind: "login",
          path: ["Devices"],
          fields: [
            { name: "Username", value: "admin", secret: false },
            { name: "Password", value: "synthetic-router-0003", secret: true },
          ],
          notes: "Synthetic vector.\nSecond line.",
        },
      ],
    },
  }),
];

/** A domain of exactly `length` bytes: labels of 63 bytes, then the rest, then `example`. */
function domainOf(length) {
  const labels = [];
  let left = length - "example".length;
  while (left > 64) {
    labels.push("a".repeat(63));
    left -= 64;
  }
  labels.push("b".repeat(left - 1));
  return [...labels, "example"].join(".");
}

const addressCases = [
  [" Ada.Lovelace@Example.COM ", "white space and case"],
  ["\tgrace@BÜCHER.example.\n", "IDNA and a trailing dot"],
  ["o'brien+tag@sub.example.org", "no provider rule for + or dots"],
  ["user@straße.example", "ß stays (non-transitional) and becomes Punycode"],
  ["user@STRASSE.example", "ss is another domain than ß"],
  ["user@example。com", "the full-width dot maps to ."],
  ["user@ＥＸＡＭＰＬＥ.com", "full-width letters map to ASCII"],
  ["user@example.com。", "a trailing full-width dot is a trailing dot"],
  ["user@example.com..", "only one trailing dot goes"],
  ["user@xn--bcher-kva.example", "valid Punycode stays"],
  ["user@xn--a.example", "Punycode that is not valid"],
  ["user@a.0x10", "the last label starts with a letter"],
  ["user@192.168.0.1", "an all-digit top label"],
  ["user@example.c0m", "a top label that starts with a letter"],
  ["user@" + "a".repeat(63) + ".example", "a label of 63 bytes"],
  ["user@" + "a".repeat(64) + ".example", "a label of 64 bytes"],
  ["u@" + domainOf(252), "a domain of 252 bytes: the address has 254"],
  ["u@" + domainOf(253), "a domain of 253 bytes: the address would have 255"],
  ["u@" + domainOf(254), "a domain of 254 bytes"],
  ["no-at-sign.example", "no @"],
  ["two@at@example.com", "two @"],
  ["@example.com", "no local part"],
  ["dot.@example.com", "a local part that ends with a dot"],
  ["a..b@example.com", "two dots in the local part"],
  ["zoë@example.com", "a local part that is not ASCII"],
  ["space in@example.com", "white space inside"],
  ["user@localhost", "one label"],
  ["user@-bad-.example", "a label that starts or ends with -"],
  ["user@exa_mple.com", "an underscore"],
  ["user@[127.0.0.1]", "an address literal"],
  ["a".repeat(64) + "@example.com", "a local part of 64 characters"],
  ["a".repeat(65) + "@example.com", "a local part of 65 characters"],
];

const vectors = {
  contract: "connect-share-v1",
  note: "Synthetic vectors. Made by generate_vectors.mjs; do not edit by hand.",
  origin: ORIGIN,
  tags: { id: TAG_ID, key: TAG_KEY, address: TAG_ADDRESS, seal: TAG_SEAL },
  pad: PAD,
  links,
  addresses: addressCases.map(([input, note]) => ({ input, normalized: normalizeAddress(input), note })),
};

writeFileSync(OUT, JSON.stringify(vectors, null, 2) + "\n");
console.log("wrote " + OUT);
