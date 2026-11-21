# Connect share contract v1

Date: 2026-11-21, revised on 2026-11-21 before any code (review of PR #165: codes of 8 digits and a life budget of wrong tries, mail caps of each account, service workers and the agent proxy, a tombstone of each link id, `https:` origins, the uniform code answer, the size check and the retry of a creation, the address normal form with the Rust implementation as its reference). Revised on 2026-11-21 after the review of the relay (a daily cap of each recipient, the share of accounts without a plan, a budget of new links, the check of the mail session). Status: release A of [ADR 0047](../adr/0047-shared-folders-links-and-people.md) (public links); it ships in the release that carries vault schema 35 and the relay link routes (the relay and its edge Worker go out before the apps). Release B (shares with a person) adds its sections later; section 12 reserves their names.
Fixtures: [`tests/fixtures/connect-share-v1/`](../../tests/fixtures/connect-share-v1/), made by `generate_vectors.mjs` with WebCrypto and checked with `ring` by `contracts::connect_share_v1_*` in `tests/contracts.rs`, and by the viewer test `crates/apassy-relay/deploy/worker/test/share.test.ts`.
Decision: [ADR 0047](../adr/0047-shared-folders-links-and-people.md) sections 4 and 6; [ADR 0037](../adr/0037-own-relay-open-source.md) section 1, D2, D3; [plans](../product/plans.md) section 3.

This contract defines the public link: what the Mac or Linux computer seals, the link text, the routes at Connect that keep, list, revoke, and open a link, the mode "Only these e-mail addresses" with its one-time code, the viewer page `/s`, the limits, and the one mail that Connect sends for a link. The account routes use the account token of [connect-account-v1](connect-account-v1.md). MUST and MUST NOT below are requirements on both sides. A change to a message, a field, or a check needs a new version of this contract.

## 1. Rules

- **The key is only in the link.** The device that makes a link makes a key `K` of 32 random bytes. `K` is in the fragment of the link and nowhere at Connect. Connect keeps the sealed form, the link id, the times, the flags, the address hashes, and counts. It never gets `K`, the seal key, a value, or a name of the snapshot.
- **A link is a snapshot.** A later change of a secret does not reach a link. A new link is a new key.
- Every account may make links, also an account without a plan (ADR 0047 section 6). The limits are in section 7.
- **One answer for a link that does not open.** An unknown, expired, revoked, or opened one-time link is `404 not_found`, with the same body, on every public route. So is a link id that Connect stored once and no longer has (section 4.1).
- Connect deletes the sealed form at the expiry, at a revoke, at the first open of a one-time link, and with the account. Links are in a file of their own (`links.db`) that is not in the backups of the relay, so no backup brings a link back.
- Requests are strict, as in connect-account-v1 section 1: unknown, duplicate, and missing fields are `400 invalid_request`. A client ignores unknown fields in a result.
- The routes of this contract exist where the account routes of connect-account-v1 exist. Elsewhere they answer `404 not_found`. A relay that you run yourself serves the same routes and the same page.
- **No script of the origin but the viewer's.** Whoever serves a script at the origin of a link can read `K` from the fragment. So a relay that serves links MUST keep any other script of its origin from running with that origin's rights (section 5.1): no service worker, and no page of the agent proxy `/p/` with the origin's rights.

## 2. Encodings

The encodings of connect-account-v1 section 2 apply: b64u without padding, lowercase hex, times as Unix seconds, the JSON envelope `{"ok":true,"result":…}` or `{"ok":false,"error":{"code":…,"message":…}}`.

| Value | Form |
| --- | --- |
| Link key `K` | 32 random bytes; in the link as b64u (43 characters) |
| Link | `<origin>/s#v1.<K>`. `origin` is the Connect origin of the account, as the app stores it (relay-sync-v1 section 3) and as a browser shows it in `location.origin`: lowercase scheme and host, the port only when it is not the default, no path, no trailing slash. The scheme is `https:`; `http:` only for `http://localhost` and `http://127.0.0.1` with or without a port, for tests. The app makes no link for another origin (a node origin, an address of a LAN, a `.onion` name): a browser has no WebCrypto there, or the origin is not the one that the reader can reach. The hosted link is `https://apassy-relay.wyderka.cc/s#v1.<K>` |
| Link id | 32 lowercase hex: the first 16 bytes of HKDF (section 3) with the info `apassy-connect public-link id v1` |
| Sealed form | b64u of the 12-byte nonce followed by the AES-256-GCM ciphertext and its 16-byte tag |
| Access mode | `anyone` ("Anyone with the link") or `emails` ("Only these e-mail addresses") |
| One-time flag | JSON `true` or `false`; in the associated data `1` or `0` |
| Address key | b64u of 32 bytes of HKDF with the info `apassy-connect public-link address v1` (43 characters) |
| Address hash | b64u of HMAC-SHA256 under the address key of the link over the normal form of the address (section 6), 43 characters |
| Code | 8 decimal digits, made by Connect from a uniform random number |
| Link state | `live`, or `opened` for a one-time link after its open |

## 3. Keys, associated data, and the sealed form

- **HKDF** is HKDF-SHA256 (RFC 5869) with `K` as the input key, an empty salt, and the tag as the info. Each tag gives one value:

  | Info | Length | Value |
  | --- | --- | --- |
  | `apassy-connect public-link id v1` | 16 bytes | the link id |
  | `apassy-connect public-link key v1` | 32 bytes | the AES-256-GCM seal key |
  | `apassy-connect public-link address v1` | 32 bytes | the address key (section 6) |

- **The associated data** is these parts joined with one `0x00` byte, no trailing `0x00`: `apassy-connect public-link v1`, the origin, the link id (hex), the expiry (decimal), the one-time flag (`1` or `0`), and the access mode. A viewer builds it from the answer of the open (section 4.4) and from `location.origin`. So a Connect that changes the expiry, the flag, or the mode of a link, or a link that is opened at another origin, does not open. The origin stays in the associated data although the viewer reads it from the page: a relay MUST NOT redirect `/s`, `/share.js`, or `/share.css` (section 5), and a copy of the page at another origin opens no link.
- **The nonce** is 12 random bytes. A device seals once with one key: new content, also the same secret after a change, always gets a new `K`, so a new link id and a new nonce.
- **The snapshot** is one JSON object in UTF-8:

  ```json
  {"v":1,"title":"Staging database","items":[{"title":"Staging database","kind":"database","path":[],"fields":[{"name":"Host","value":"db.staging.example","secret":false},{"name":"Password","value":"…","secret":true}],"notes":""}]}
  ```

  | Field | Rule |
  | --- | --- |
  | `v` | `1`. A viewer shows a snapshot of another version as a link that does not open |
  | `title` | The name of the secret or the folder, 1 to 128 bytes |
  | `items` | 1 to 100 items. A link of one secret has one item |
  | `items[].title` | 1 to 128 bytes |
  | `items[].kind` | `api_key`, `login`, `ssh_key`, `database`, or `custom`. A viewer shows another kind as an item |
  | `items[].path` | The folder path inside the shared folder, each name 1 to 64 bytes, `[]` at its top and for a link of one secret. Never a folder above the shared folder |
  | `items[].fields` | 0 to 64 fields of `name` (the label that the app shows, 1 to 64 bytes), `value` (text), and `secret` (the viewer hides it until the reader asks) |
  | `items[].notes` | Text, may be empty |

  A snapshot never holds a one-time-code seed, a passkey field, an archived credential, the history, an item id, a folder outside the shared folder, or a secret that the account received from someone else.
- **Padding.** The plaintext is the JSON text followed by spaces (`0x20`) up to the next multiple of 1024 bytes, at least 1024 and at most 32768. JSON allows the spaces, so a reader parses the whole plaintext. Without the padding Connect would see the length of the names and values.
- The sealed form of 32768 bytes of plaintext is 32796 bytes, 43728 characters of b64u, so the creation body stays below the JSON limit of 64 KiB with the address hashes.
- **The app checks the size before the owner check.** A snapshot whose padded plaintext would exceed 32768 bytes is refused before `CreatePublicLink` is asked, and the app says how many of the chosen secrets fit (the most, in the order of the list, whose snapshot fits). It never cuts a value.

## 4. Routes

| Route | Auth | Section |
| --- | --- | --- |
| `POST /v1/account/links` | account token | 4.1 |
| `GET /v1/account/links` | account token | 4.2 |
| `DELETE /v1/account/links/{link_id}` | account token, the account that made the link | 4.3 |
| `POST /v1/links/{link_id}/open` | edge (no `Authorization`) | 4.4 |
| `POST /v1/links/{link_id}/code` | edge (no `Authorization`) | 4.5 |

The public routes refuse an `Authorization` header with `400 invalid_request`. Every answer of this contract carries `Cache-Control: no-store`, and the public ones also `Referrer-Policy: no-referrer`. Every answer of the routes of this section, errors included, carries the header `x-apassy-links: 1`: it tells an answer of these routes from one of a relay that does not have them (an older image, a route that does not exist). Connect logs no link id with a client address, and no address.

### 4.1 `POST /v1/account/links`

```json
{"link_id":"d4e59a0011f71c40fb1dfdb1a8446660","sealed":"<b64u>","expires_at":1764331200,"one_time":false,"access":"anyone","address_hashes":[]}
```

- `link_id` is 32 lowercase hex. Connect cannot check that it comes from the key; the viewer finds a link only by the id that the key gives.
- `sealed` is 28 bytes more than a plaintext of section 3: from 1052 to 32796 bytes, and its length minus 28 is a multiple of 1024. Else `400 invalid_request`.
- `expires_at` is at least 540 and at most 2592060 seconds after Connect's clock (10 minutes to 30 days, with 60 seconds for the clocks). Else `400 invalid_request`.
- `access` `anyone` has `address_hashes` `[]`. `access` `emails` has 1 to 20 distinct address hashes. Else `400 invalid_request`. A relay without a mail sender (section 10) refuses `emails` with `503 mail_unavailable`.
- Over the live links of the account (section 7) the answer is `403 link_limit`, and nothing is kept. An opened one-time link does not count.
- Over the new links of the account in the UTC day (section 7) the answer is `429 link_create_limit` with `Retry-After` until the day ends, and nothing is kept. Connect checks it before any write; every creation that is not a retry counts, also one that is refused. A client shows that the account made as many links as it may today, and tries no automatic retry before `Retry-After`.
- **A link id is used once.** Connect keeps a tombstone of every link id that it ever stored (`link_id_used` in `links.db`: the id only, no account, no time, never deleted). A creation with a used id is `409 conflict`, also after the link expired or was revoked. The public routes answer `404 not_found` for it.
- **Retry.** The device that sends a creation keeps the exact body (the same `K`, the same sealed form) until it gets an answer. The same `link_id` with the same body from the same account, while the link lives, answers the stored view again, so a lost answer can be sent again. Any other body with a used id is `409 conflict`. A device that gets `409 conflict` for its own retry reads `GET /v1/account/links`: a link that is listed was made; one that is not was not, and the device makes a new `K` for another try.
- The answer is the view of the link (section 4.2).

The device that makes a link keeps it in the vault table `public_link` ([vault-v1](vault-v1.md), schema 35) with `K`, so each device of the owner lists it, copies the link again, and revokes it. The app makes a link only after the owner check `CreatePublicLink`, which names the secrets, the expiry, the one-time flag, the access mode, and the addresses (ADR 0047 section 4).

### 4.2 `GET /v1/account/links`

```json
{"links":[{"link_id":"d4e59a0011f71c40fb1dfdb1a8446660","created_at":1763726400,"expires_at":1764331200,"one_time":false,"access":"anyone","addresses":0,"state":"live","opens":2,"last_opened_at":1763730000}],"live":1,"limit":25,"mail":true}
```

- The links of the account that did not expire and were not revoked, the newest first. `addresses` is the count of address hashes. `opens` counts the answers with a sealed form (section 4.4). `last_opened_at` is `null` before the first.
- `live` is the count of section 7, `limit` its limit (`null` for no limit), and `mail` whether this relay can send the code mail now (section 10): `false` without a mail sender, and while the relay's check of its mail session fails.

### 4.3 `DELETE /v1/account/links/{link_id}`

- Deletes the row, the sealed form, the address hashes, and the codes of the link in one transaction. The answer is `{"link_id":"…","deleted":true}`. From that moment the public routes answer `404 not_found`.
- A link of another account, and an unknown one, is `404 not_found`. A client takes a `404` for a revoke that is done only when the answer carries `x-apassy-links: 1` (section 4). A `404` without it (a route that this relay does not serve, such as an image before public links, or an edge in front of one) means that the revoke is **not** done: the client keeps it and tries again later, so a link that its owner revoked never comes back with the newer image.
- A revoke needs no owner check.

### 4.4 `POST /v1/links/{link_id}/open`

```json
{"confirm":false,"email":null,"address_key":null,"code":null}
```

- `email`, `address_key`, and `code` are all `null` or all set. They are set only for a link with the access `emails`, after a code (section 4.5); else `400 invalid_request`. When set, `email` has a normal form (section 6), `address_key` is 32 bytes, and `code` is 8 decimal digits; else `400 invalid_request`. Connect MUST NOT store or log `address_key` here either.
- The answer:

  ```json
  {"expires_at":1764331200,"one_time":false,"access":"anyone","sealed":"<b64u>"}
  ```

  `sealed` is the sealed form, or `null` when the reader must act first:

  | Link | Request | `sealed` |
  | --- | --- | --- |
  | `anyone`, not one-time | any `confirm` | the sealed form |
  | `anyone`, one-time | `confirm` `false` | `null`; nothing changes |
  | `anyone`, one-time | `confirm` `true` | the sealed form, and Connect deletes it in the same transaction |
  | `emails` | no code | `null`; nothing changes |
  | `emails`, not one-time | a valid code | the sealed form; the code is used |
  | `emails`, one-time | a valid code and `confirm` `false` | `null`; the code stays and no try counts |
  | `emails`, one-time | a valid code and `confirm` `true` | the sealed form; the code is used and Connect deletes the sealed form in the same transaction |

- So a link of `anyone` that is not one-time opens with one request, and a one-time link opens only after the reader said yes. Of two opens of a one-time link at the same moment, one gets the sealed form and the other `404 not_found`.
- A code is valid when Connect holds a live code for this link and the address hash of `email` under `address_key` (section 6), and `code` is that code. Any other code, an address that is not on the link, a code that ended, and a pair of link and address that used its wrong tries (section 7) are `403 code_invalid`, with the same statements; with a live code, its try is also written. A wrong try counts only while a code is live for that link and address: each `403 code_invalid` of a live code counts a try of that code (the fifth ends the code) and a wrong try of the pair over the life of the link (the tenth ends codes for that pair: no new code is sent to that address for that link, and the answers stay the same). A guess with no live code is `403 code_invalid` and counts nothing, so a holder of the link cannot lock a reader out without a mail to that reader.
- An unknown, expired, revoked, or opened link is `404 not_found` (section 1), before any other check of the body except its form.

### 4.5 `POST /v1/links/{link_id}/code`

```json
{"email":"ada.lovelace@example.com","address_key":"<b64u>"}
```

- **The answer comes before any look at the addresses.** Connect checks, in this order and only these: the form of the body; that `email` has a normal form (section 6; else `400 invalid_request`) and `address_key` is 32 bytes; that the link is live and has the access `emails` (else `404 not_found`); that the relay has a mail sender whose session passes its check (section 10) and that neither the daily mail cap of the sharing account, nor the share of the accounts without a plan (for an account without one), nor the cap of the relay is reached (else `503 mail_unavailable`); and the code requests of the link (section 7; else `429 rate_limited`). None of these depends on the address. It then answers `{"expires_in":900}` and hands the normal form, the address key, and the link id in memory to the mail thread.
- **The mail thread** makes the address hash and compares it with the hashes of the link. When it is one of them, the pair of link and address has codes left for the UTC day and wrong tries left over the life of the link, and the recipient has mails left for the UTC day across all links and accounts (section 7), it makes a code, ends the code before for that pair, writes the code row and the outbox row (section 10) in one transaction, and counts the mail for the account and the relay. Otherwise it writes nothing and sends nothing. The request has its answer before any of this, so both paths are the same on the wire and in time.
- **Accepted.** Two signals can tell a holder of `K` whether the mail thread made a mail for an address they asked for: a relay near its daily cap answers the next request with `503 mail_unavailable` or not; and the transaction of the mail thread, which runs the same statements on both paths, writes rows only when it makes a code, so its lock of `links.db` and its commit take a little longer then, which a request at the same moment may see. A holder of `K` learns from either only whether an address they guessed is on the link, and that reader gets a mail. Without `K` neither signal says anything about an address.
- Only the person who reads the mail learns that the address may open the link.
- Above a mail cap, every code request of that link gets `503 mail_unavailable`, whatever the address, until the UTC day ends.
- Connect MUST NOT store or log `address_key`: it lives in the memory of the request and of the mail thread only, and goes when the thread has handled it.

## 5. The viewer page `/s`

- Connect serves the page at `<origin>/s`, with its script at `/share.js` and its style at `/share.css`. Only `GET` and `HEAD`, each answered with the file itself: a relay MUST NOT redirect these three paths. The hosted page comes from the edge Worker (`crates/apassy-relay/deploy/worker/public/`); a relay that you run yourself serves the same three files.
- Headers of the three answers: `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex, nofollow`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`. The page has no inline script, no inline style, and no event attribute.
- The page has one fixed title, "Shared with Apassy". It never shows the name of a secret or a folder in the title, which goes to the browser's history, its sync, and the tab list.
- The script has no dependency and no build step. It uses WebCrypto only. Without `crypto.subtle` (a page that is not in a secure context) it says that the link opens only over HTTPS, and sends nothing.
- Its steps:
  1. It reads the fragment and takes it out of the address bar (`history.replaceState` to `/s`) before any request. This changes the URL of the current entry of the tab's history only: the browser may have written the whole link to its global history, and to the sync of that history, when the tab opened it.
  2. It derives the link id, the seal key, and the address key, and sends `POST /v1/links/{link_id}/open` to its own origin with `confirm` `false`. It loads nothing from another origin; for a link of `anyone` that is not one-time, this is its only request.
  3. A one-time link: it says that the content shows once, and opens with `confirm` `true` only after the reader's yes.
  4. A link of `emails`: it asks for the address, sends `POST /v1/links/{link_id}/code`, asks for the code, and opens with the code (and `confirm` `true`; for a one-time link it says first that the content shows once).
  5. It builds the associated data from the answer and `location.origin`, opens the sealed form, refuses a snapshot whose expiry has passed by the reader's clock, and shows the items. Secret values stay hidden until the reader asks; "Copy" writes one value to the clipboard.
- One text for every `404`: the link does not open; it may have expired, been revoked, or been opened already. A sealed form that does not open gets the same text. The page never names which case it was. A `400` (an address without a normal form) and a `503 mail_unavailable` have texts of their own, and only an answer that a new try can change (no answer, a `5xx` other than `mail_unavailable`) offers "Try Again".

### 5.1 Other scripts of the origin

A relay that serves links MUST hold these, on its own listener and at its edge:

- It refuses every request that carries the header `Service-Worker: script`, on every path, with `400 invalid_request`. A browser sends that header only to fetch the script of a service worker; so no service worker is registered at the origin, and none can answer for `/s` or `/share.js`.
- Every answer of the agent proxy `/p/` (relay SPEC section 12) has no `Service-Worker-Allowed` header (the relay removes one that the upstream sent) and carries `Content-Security-Policy: sandbox` in addition to any policy of the upstream. So a page that the proxy relays runs in an opaque origin, never with the rights of the link's origin.
- It serves no other HTML or script at that origin with the origin's rights. The routes of relay-sync-v1 and connect-account-v1 answer JSON or bytes.
- It writes every text of the snapshot as text, never as markup. It keeps nothing: no storage, no cookie. It never asks for a password, a passphrase, or an account.

## 6. Addresses

**The normal form** of an address, on the Mac, on Linux, and at Connect:

1. Remove white space (space, tab, CR, LF) at the start and at the end.
2. The text holds exactly one `@`. Before it is the local part, after it the domain.
3. The local part has 1 to 64 characters of `` A-Z a-z 0-9 ! # $ % & ' * + - / = ? ^ _ ` { | } ~ . ``, does not start or end with `.`, and has no `..`. It becomes lowercase (ASCII). Nothing else changes: no dot or `+` rule of one mail provider.
4. The ASCII characters of the domain are only `A-Z a-z 0-9 . -`. The domain becomes its ASCII form by UTS #46 ToASCII, non-transitional (so `ß` stays and becomes `xn--…`, and `。` becomes `.`), as `idna::domain_to_ascii` of the crate `idna` 1.1 does. A domain that it refuses (for example a label `xn--a` that is not valid Punycode) has no normal form. Then the ASCII form loses one trailing `.`.
5. The result has at most 253 bytes and at least two labels, each label 1 to 63 bytes of `a-z 0-9 -` that does not start or end with `-`, and the last label starts with a letter `a-z` (so no address literal, no `a.0x10`, no all-digit top label).
6. The result `local@domain` has at most 254 bytes. So the longest domain that has a normal form is 252 bytes long, with a local part of one character.

A text without a normal form is not an address: the app does not take it, and Connect answers `400 invalid_request`.

**The reference is the Rust implementation** of these steps, with `idna::domain_to_ascii` (the test helper `connect_share_v1::normalize` in `tests/contracts.rs` and the code of the app and the relay). The vectors of section 9 give its results. Another implementation (the generator's WHATWG URL parser) MUST give the same results for the vectors, and on a difference the Rust result is the normal form.

**The address hash** is the HMAC-SHA256 of the normal form (UTF-8) under the address key of the link, as b64u. The address key comes from `K`, so the hashes of two links differ for one address, and the hashes in `links.db` do not give an address to someone without the link. Connect learns the address key of a link when a reader asks for a code (section 4.5), and the address in that request. Connect MUST NOT store or log the address key. A Connect that keeps it anyway can test guessed addresses against the hashes of that one link (trust model, "Public links").

## 7. Limits

| Limit | Value |
| --- | --- |
| Live links of an account without a plan, on Connect Personal, or on Connect Family | 25 |
| Live links of a Connect Team member | 100 |
| Live links on a relay that you run yourself | no plan limit |
| Expiry | 10 minutes to 30 days; the app's default is 7 days |
| Padded plaintext | 1 KiB to 32 KiB, a multiple of 1 KiB |
| Addresses of a link | 1 to 20 |
| A code | 8 digits, 15 minutes, 5 tries, one live code for each link and address |
| Wrong tries of a link and address | 10 over the life of the link; only a wrong code while a code is live counts; then no new code for that address and that link, and every answer stays the same |
| Codes of a link and address | 5 each UTC day, counted by the mail thread; above it no mail, and the answer stays the same |
| Code requests of a link | 20 an hour, every request counted, before any look at the address; then `429 rate_limited` |
| Code mails of a sharing account, each UTC day | 50 for an account without a plan, on Connect Personal, or on Connect Family; 200 for a Connect Team member; a setting of the operator on a relay with open plans. Counted before the cap of the relay; above it `503 mail_unavailable` for every code request of the account's links |
| Code mails of all accounts without a plan together, each UTC day | a share of the relay's cap (default 500 of 2000), so the accounts on a plan keep the rest; above it `503 mail_unavailable` for every code request of their links until the day ends |
| Code mails of a relay, each UTC day | a cap of the operator (default 2000); above it `503 mail_unavailable` until the day ends |
| Code mails to one address, each UTC day | 10, across all links and accounts, counted by the mail thread under the normal form without a `+tag` of the local part, and for `gmail.com` and `googlemail.com` without its dots (one inbox, one count; the mail goes to the address as typed); above it no mail, and the answer stays the same. So a sharer who requests the codes of an address on their own links can use up its mails for the day: another sharer's code mail to it waits for the next day |
| New links of an account, each UTC day | 100; 400 for a Connect Team member; none on a relay with open plans. Then `429 link_create_limit` |
| A mail lost to the relay's own settings | A mail that fails before its recipient is named (the connection, TLS, AUTH, `MAIL FROM`) counts for no cap of the account, the address, or the pair of link and address; a refused recipient counts. Only a `5xx` at AUTH or `MAIL FROM` (or a server without AUTH) stops the mail until the next check passes; a `4xx` there is a busy server, and the mail waits for its next try |
| Worker, for each IPv4 address or IPv6 /64 | `LINK_LIMITER`: 30 opens a minute; `LINK_CODE_LIMITER`: 5 code requests a minute; `LINK_WRITE_LIMITER`: 20 creations and revokes a minute; then `429 rate_limited` with `Retry-After: 60` |

The plan limits are Connect's settings with these defaults. The live links of an account count in the transaction that adds one. When a plan ends, the links stay until their expiry; a new link counts against the new limit.

## 8. Errors

The codes of relay-sync-v1 and connect-account-v1 section 4 keep their meaning: `invalid_request` 400, `unauthenticated` 401, `account_required` 403, `not_found` 404, `conflict` 409, `payload_too_large` 413, `rate_limited` 429. This contract adds:

| Status | Code | When |
| --- | --- | --- |
| 403 | `link_limit` | `POST /v1/account/links` over the live links of the account (section 7) |
| 429 | `link_create_limit` | `POST /v1/account/links` over the new links of the account in the UTC day (section 7), with `Retry-After` |
| 403 | `code_invalid` | `POST /v1/links/{link_id}/open` with a code that is not the live code of this link and address, also for an address that is not on the link and a code that ended |
| 503 | `mail_unavailable` | A link of `emails` or a code request on a relay without a mail sender, or while its mail session fails its check; a code request above the daily mail cap of the sharing account, of the accounts without a plan, or of the relay, the same for every address |

A `403 link_limit` and a `429 link_create_limit` name the limit and never a price or a purchase hint: the iPhone shows no plan change (connect-billing-v1 section 10).

## 9. Test vectors

`tests/fixtures/connect-share-v1/link-vectors.json` holds three links of the origin `https://apassy-relay.wyderka.cc`, synthetic keys only:

- `anyone`: one secret, not one-time, access `anyone`.
- `one_time_anyone`: one secret, one-time, access `anyone`.
- `one_time_emails`: a folder of two secrets, one of them in a subfolder, one-time, access `emails`, with two addresses.

Each link has its key, the link text, the link id, the seal key, the address key, the snapshot, the JSON length, the padded plaintext, the associated data, the nonce, the sealed form, its addresses with their normal forms and hashes, and the body of `POST /v1/account/links`. The list `addresses` holds texts with their normal form, or `null` when there is none, and a `note` for the edge cases: white space and case, `ß` (non-transitional), `。`, a trailing dot, Punycode that is not valid (`xn--a`), `a.0x10`, an all-digit top label, labels of 63 and 64 bytes, and domains of 252, 253, and 254 bytes. `generate_vectors.mjs` makes the file with WebCrypto in Node and gives the same file at each run.

## 10. Connect mail

Connect sends one kind of mail in this release: the code of section 4.5.

- From the sender of the relay (hosted: `connect@apassy.wyderka.cc`), to the address that the reader typed, in its normal form.
- Plain text, no link, no image, no tracking, no name of the person who made the link:

  ```text
  Subject: Your Apassy code

  Your code to open a shared Apassy item: 12345678

  It works for 15 minutes. If you did not ask for it, ignore this mail.
  ```

- The mail thread of section 4.5 writes the mail to an outbox in `links.db`, and a sender hands it to the SMTP server of the operator (submission with TLS). A sent mail leaves the outbox at once; a mail that cannot be sent within one hour is deleted. The address is in the outbox only, never in a log.
- A relay without a mail sender has no `emails` links (section 4.1).
- **The check of the session.** A relay with a mail sender checks its session at start and then every few minutes (hosted: 5): the connection, TLS, EHLO, AUTH, and the sender, with no recipient and no mail. While that check fails, and after a mail fails at AUTH or at the sender until a check passes, the relay sends no code mail: `mail` is `false` (section 4.2), and a link of `emails` and a code request answer `503 mail_unavailable`.

## 11. What Connect stores

| Where | What | How long |
| --- | --- | --- |
| `links.db`, link row | The link id, the account id, the times, the one-time flag, the access mode, `opens`, `last_opened_at`, the counts of codes that did not open and of code requests that the mail thread handled (one write on every path), the sealed form | Until the expiry, the revoke, or the account's deletion. A one-time link loses its sealed form and its address hashes at its open; its row stays until its expiry, for the list of section 4.2 |
| `links.db`, address hashes | The address hashes of a link of `emails` | With the link |
| `links.db`, codes | A hash of each code with the link id, the address hash, its expiry, and its tries | 15 minutes, or the fifth wrong try, or its use |
| `links.db`, pairs | For each link and address hash that got a code: the wrong tries over the life of the link, and the codes of the UTC day | With the link |
| `links.db`, used ids | Every link id that Connect ever stored, alone | Never deleted |
| `links.db`, mail counts | The code mails of each account, of all accounts without a plan together, and of the relay for the UTC day | Until the day ends |
| `links.db`, recipient counts | The code mails of each recipient for the UTC day, under an HMAC-SHA256 of the normal form of its address keyed by a random secret of the relay (kept in `links.db`, made at its first open); never the address. Whoever reads `links.db` can test a guessed address against the hashes of that day | One day: the rows of a past day are deleted |
| `links.db`, new links | The count of new links of each account for the UTC day | Until the day ends |
| `links.db`, outbox | The address and the text of a code mail | Until it is sent, at most 1 hour |
| Memory | The other counts of section 7; the address key and the normal form of a code request, until the mail thread has handled it; for each mail in the outbox, what it counted (so a mail lost to the relay's own settings gives it back) | Their window; with the mail |

`links.db` is not in the backups of the relay. Connect never stores `K`, the seal key, an address key, or a client address with a link id.

## 12. Reserved for release B

Release B of ADR 0047 (shares with a person) adds sections to this contract and changes none of sections 1 to 11. These names are reserved for it:

- Routes: `PUT /v1/account/email` and `POST /v1/account/email/verify` (the verified address of an account), `/v1/account/collections/…` (collections, the member log, invitations, sealed share keys, edit slots, edit requests, leave).
- Tags: `apassy-connect collection-log v1`, `apassy-connect share-accept v1`, `apassy-connect share-leave v1`, `apassy-connect share-edit v1`, `apassy-connect share-key v1`.
- Codes: `share_limit`, `email_required`, `email_mismatch`.
- The invitation mail: Connect sends it with the link of the invitation to the address that the sharer named; the person verifies that address on their account with a code before they accept.
- The normal form of section 6 is also the form of an account's address; the hash of release B is its own.
