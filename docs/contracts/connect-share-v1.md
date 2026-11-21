# Connect share contract v1

Date: 2026-11-21. Status: frozen for implementation of release A of [ADR 0047](../adr/0047-shared-folders-links-and-people.md) (public links); not built. Release B (shares with a person) adds its sections later; section 12 reserves their names.
Fixtures: [`tests/fixtures/connect-share-v1/`](../../tests/fixtures/connect-share-v1/), made by `generate_vectors.mjs` with WebCrypto and checked with `ring` by `contracts::connect_share_v1_*` in `tests/contracts.rs`, and by the viewer test `crates/apassy-relay/deploy/worker/test/share.test.ts`.
Decision: [ADR 0047](../adr/0047-shared-folders-links-and-people.md) sections 4 and 6; [ADR 0037](../adr/0037-own-relay-open-source.md) section 1, D2, D3; [plans](../product/plans.md) section 3.

This contract defines the public link: what the Mac or Linux computer seals, the link text, the routes at Connect that keep, list, revoke, and open a link, the mode "Only these e-mail addresses" with its one-time code, the viewer page `/s`, the limits, and the one mail that Connect sends for a link. The account routes use the account token of [connect-account-v1](connect-account-v1.md). MUST and MUST NOT below are requirements on both sides. A change to a message, a field, or a check needs a new version of this contract.

## 1. Rules

- **The key is only in the link.** The device that makes a link makes a key `K` of 32 random bytes. `K` is in the fragment of the link and nowhere at Connect. Connect keeps the sealed form, the link id, the times, the flags, the address hashes, and counts. It never gets `K`, the seal key, a value, or a name of the snapshot.
- **A link is a snapshot.** A later change of a secret does not reach a link. A new link is a new key.
- Every account may make links, also an account without a plan (ADR 0047 section 6). The limits are in section 7.
- **One answer for a link that does not open.** An unknown, expired, revoked, or opened one-time link is `404 not_found`, with the same body, on every public route.
- Connect deletes the sealed form at the expiry, at a revoke, at the first open of a one-time link, and with the account. Links are in a file of their own (`links.db`) that is not in the backups of the relay, so no backup brings a link back.
- Requests are strict, as in connect-account-v1 section 1: unknown, duplicate, and missing fields are `400 invalid_request`. A client ignores unknown fields in a result.
- The routes of this contract exist where the account routes of connect-account-v1 exist. Elsewhere they answer `404 not_found`. A relay that you run yourself serves the same routes and the same page.

## 2. Encodings

The encodings of connect-account-v1 section 2 apply: b64u without padding, lowercase hex, times as Unix seconds, the JSON envelope `{"ok":true,"result":…}` or `{"ok":false,"error":{"code":…,"message":…}}`.

| Value | Form |
| --- | --- |
| Link key `K` | 32 random bytes; in the link as b64u (43 characters) |
| Link | `<origin>/s#v1.<K>`. `origin` is the Connect origin of the account, as the app stores it (relay-sync-v1 section 3) and as a browser shows it in `location.origin`: lowercase scheme and host, the port only when it is not the default, no path, no trailing slash. The hosted link is `https://apassy-relay.wyderka.cc/s#v1.<K>` |
| Link id | 32 lowercase hex: the first 16 bytes of HKDF (section 3) with the info `apassy-connect public-link id v1` |
| Sealed form | b64u of the 12-byte nonce followed by the AES-256-GCM ciphertext and its 16-byte tag |
| Access mode | `anyone` ("Anyone with the link") or `emails` ("Only these e-mail addresses") |
| One-time flag | JSON `true` or `false`; in the associated data `1` or `0` |
| Address key | b64u of 32 bytes of HKDF with the info `apassy-connect public-link address v1` (43 characters) |
| Address hash | b64u of HMAC-SHA256 under the address key of the link over the normal form of the address (section 6), 43 characters |
| Code | 6 decimal digits, made by Connect |
| Link state | `live`, or `opened` for a one-time link after its open |

## 3. Keys, associated data, and the sealed form

- **HKDF** is HKDF-SHA256 (RFC 5869) with `K` as the input key, an empty salt, and the tag as the info. Each tag gives one value:

  | Info | Length | Value |
  | --- | --- | --- |
  | `apassy-connect public-link id v1` | 16 bytes | the link id |
  | `apassy-connect public-link key v1` | 32 bytes | the AES-256-GCM seal key |
  | `apassy-connect public-link address v1` | 32 bytes | the address key (section 6) |

- **The associated data** is these parts joined with one `0x00` byte, no trailing `0x00`: `apassy-connect public-link v1`, the origin, the link id (hex), the expiry (decimal), the one-time flag (`1` or `0`), and the access mode. A viewer builds it from the answer of the open (section 4.4) and from `location.origin`. So a Connect that changes the expiry, the flag, or the mode of a link, or a link that is opened at another origin, does not open.
- **The nonce** is 12 random bytes. A device seals once with one key.
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

## 4. Routes

| Route | Auth | Section |
| --- | --- | --- |
| `POST /v1/account/links` | account token | 4.1 |
| `GET /v1/account/links` | account token | 4.2 |
| `DELETE /v1/account/links/{link_id}` | account token, the account that made the link | 4.3 |
| `POST /v1/links/{link_id}/open` | edge (no `Authorization`) | 4.4 |
| `POST /v1/links/{link_id}/code` | edge (no `Authorization`) | 4.5 |

The public routes refuse an `Authorization` header with `400 invalid_request`. Every answer of this contract carries `Cache-Control: no-store`, and the public ones also `Referrer-Policy: no-referrer`. Connect logs no link id with a client address, and no address.

### 4.1 `POST /v1/account/links`

```json
{"link_id":"d4e59a0011f71c40fb1dfdb1a8446660","sealed":"<b64u>","expires_at":1764331200,"one_time":false,"access":"anyone","address_hashes":[]}
```

- `link_id` is 32 lowercase hex. Connect cannot check that it comes from the key; the viewer finds a link only by the id that the key gives.
- `sealed` is 28 bytes more than a plaintext of section 3: from 1052 to 32796 bytes, and its length minus 28 is a multiple of 1024. Else `400 invalid_request`.
- `expires_at` is at least 540 and at most 2592060 seconds after Connect's clock (10 minutes to 30 days, with 60 seconds for the clocks). Else `400 invalid_request`.
- `access` `anyone` has `address_hashes` `[]`. `access` `emails` has 1 to 20 distinct address hashes. Else `400 invalid_request`. A relay without a mail sender (section 10) refuses `emails` with `503 mail_unavailable`.
- Over the live links of the account (section 7) the answer is `403 link_limit`, and nothing is kept. An opened one-time link does not count.
- The same `link_id` with the same body from the same account answers the stored view again, so a lost answer can be sent again. Any other body with a known id is `409 conflict`.
- The answer is the view of the link (section 4.2).

The device that makes a link keeps it in the vault table `public_link` ([vault-v1](vault-v1.md), schema 35) with `K`, so each device of the owner lists it, copies the link again, and revokes it. The app makes a link only after the owner check `CreatePublicLink`, which names the secrets, the expiry, the one-time flag, the access mode, and the addresses (ADR 0047 section 4).

### 4.2 `GET /v1/account/links`

```json
{"links":[{"link_id":"d4e59a0011f71c40fb1dfdb1a8446660","created_at":1763726400,"expires_at":1764331200,"one_time":false,"access":"anyone","addresses":0,"state":"live","opens":2,"last_opened_at":1763730000}],"live":1,"limit":25,"mail":true}
```

- The links of the account that did not expire and were not revoked, the newest first. `addresses` is the count of address hashes. `opens` counts the answers with a sealed form (section 4.4). `last_opened_at` is `null` before the first.
- `live` is the count of section 7, `limit` its limit (`null` for no limit), and `mail` whether this relay can send the code mail (section 10).

### 4.3 `DELETE /v1/account/links/{link_id}`

- Deletes the row, the sealed form, the address hashes, and the codes of the link in one transaction. The answer is `{"link_id":"…","deleted":true}`. From that moment the public routes answer `404 not_found`.
- A link of another account, and an unknown one, is `404 not_found`. A client takes a `404` for a revoke that is done.
- A revoke needs no owner check.

### 4.4 `POST /v1/links/{link_id}/open`

```json
{"confirm":false,"email":null,"address_key":null,"code":null}
```

- `email`, `address_key`, and `code` are all `null` or all set. They are set only for a link with the access `emails`, after a code (section 4.5); else `400 invalid_request`.
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
- A code is valid when Connect holds a live code for this link and the address hash of `email` under `address_key` (section 6), and `code` is that code. Any other code, an address that is not on the link, and a code that ended are `403 code_invalid`. Each `403 code_invalid` of a live code counts a try; the fifth ends the code.
- An unknown, expired, revoked, or opened link is `404 not_found` (section 1), before any other check of the body except its form.

### 4.5 `POST /v1/links/{link_id}/code`

```json
{"email":"ada.lovelace@example.com","address_key":"<b64u>"}
```

- For a live link with the access `emails`. Any other link is `404 not_found`.
- `email` is the text that the reader typed. Connect makes its normal form (section 6); a text that has none is `400 invalid_request`. `address_key` is the address key of the link (32 bytes).
- When the address hash is one of the link, Connect makes a code, ends the code before for that link and address, and sends the mail of section 10. When it is not, Connect sends nothing.
- **The answer is the same in both cases**: `{"expires_in":600}`, after the same work. Only the person who reads the mail learns that the address may open the link.
- The limits of section 7 count every request, with or without a mail, so a `429 rate_limited` tells nothing about an address either.
- A relay without a mail sender answers `503 mail_unavailable`.

## 5. The viewer page `/s`

- Connect serves the page at `<origin>/s`, with its script at `/share.js` and its style at `/share.css`. Only `GET` and `HEAD`. The hosted page comes from the edge Worker (`crates/apassy-relay/deploy/worker/public/`); a relay that you run yourself serves the same three files.
- Headers of the three answers: `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex, nofollow`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin`. The page has no inline script, no inline style, and no event attribute.
- The script has no dependency and no build step. It uses WebCrypto only.
- Its steps:
  1. It reads the fragment and takes it out of the address bar (`history.replaceState` to `/s`) before any request.
  2. It derives the link id, the seal key, and the address key, and sends `POST /v1/links/{link_id}/open` to its own origin with `confirm` `false`. It loads nothing from another origin; for a link of `anyone` that is not one-time, this is its only request.
  3. A one-time link: it says that the content shows once, and opens with `confirm` `true` only after the reader's yes.
  4. A link of `emails`: it asks for the address, sends `POST /v1/links/{link_id}/code`, asks for the code, and opens with the code (and `confirm` `true`; for a one-time link it says first that the content shows once).
  5. It builds the associated data from the answer and `location.origin`, opens the sealed form, refuses a snapshot whose expiry has passed by the reader's clock, and shows the items. Secret values stay hidden until the reader asks; "Copy" writes one value to the clipboard.
- One text for every `404`: the link does not open; it may have expired, been revoked, or been opened already. A sealed form that does not open gets the same text. The page never names which case it was.
- It writes every text of the snapshot as text, never as markup. It keeps nothing: no storage, no cookie. It never asks for a password, a passphrase, or an account.

## 6. Addresses

**The normal form** of an address, on the Mac, on Linux, and at Connect:

1. Remove white space (space, tab, CR, LF) at the start and at the end.
2. The text holds exactly one `@`. Before it is the local part, after it the domain.
3. The local part has 1 to 64 characters of `` A-Z a-z 0-9 ! # $ % & ' * + - / = ? ^ _ ` { | } ~ . ``, does not start or end with `.`, and has no `..`. It becomes lowercase (ASCII). Nothing else changes: no dot or `+` rule of one mail provider.
4. The domain loses one trailing `.`. Its ASCII characters are only `A-Z a-z 0-9 . -`. It becomes its ASCII form by UTS #46 (non-transitional, as URL hosts: `idna::domain_to_ascii`, `new URL("http://" + domain).hostname`). The result has at most 253 bytes and at least two labels, each label 1 to 63 of `a-z 0-9 -` and not starting or ending with `-`, and the last label is not all digits (no address literal).
5. The result `local@domain` has at most 254 bytes.

A text without a normal form is not an address: the app does not take it, and Connect answers `400 invalid_request`.

**The address hash** is the HMAC-SHA256 of the normal form (UTF-8) under the address key of the link, as b64u. The address key comes from `K`, so the hashes of two links differ for one address, and the hashes in `links.db` do not give an address to someone without the link. Connect learns the address key of a link when a reader asks for a code (section 4.5), and the address in that request.

## 7. Limits

| Limit | Value |
| --- | --- |
| Live links of an account without a plan, on Connect Personal, or on Connect Family | 25 |
| Live links of a Connect Team member | 100 |
| Live links on a relay that you run yourself | no plan limit |
| Expiry | 10 minutes to 30 days; the app's default is 7 days |
| Padded plaintext | 1 KiB to 32 KiB, a multiple of 1 KiB |
| Addresses of a link | 1 to 20 |
| A code | 10 minutes, 5 tries, one live code for each link and address |
| Code requests | 3 in 15 minutes for each link and address hash, 20 an hour for each link, also without a mail |
| Code mails of a relay | a daily cap of the operator (default 500); above it `503 mail_unavailable` until the day ends |
| Worker, for each IPv4 address or IPv6 /64 (`LINK_LIMITER`) | 30 opens and 5 code requests a minute, then `429 rate_limited` with `Retry-After: 60` |

The plan limits are Connect's settings with these defaults. The live links of an account count in the transaction that adds one. When a plan ends, the links stay until their expiry; a new link counts against the new limit.

## 8. Errors

The codes of relay-sync-v1 and connect-account-v1 section 4 keep their meaning: `invalid_request` 400, `unauthenticated` 401, `account_required` 403, `not_found` 404, `conflict` 409, `payload_too_large` 413, `rate_limited` 429. This contract adds:

| Status | Code | When |
| --- | --- | --- |
| 403 | `link_limit` | `POST /v1/account/links` over the live links of the account (section 7) |
| 403 | `code_invalid` | `POST /v1/links/{link_id}/open` with a code that is not the live code of this link and address, also for an address that is not on the link and a code that ended |
| 503 | `mail_unavailable` | A link of `emails` or a code request on a relay without a mail sender, or above its daily mail cap |

A `403 link_limit` names the limit and never a price or a purchase hint: the iPhone shows no plan change (connect-billing-v1 section 10).

## 9. Test vectors

`tests/fixtures/connect-share-v1/link-vectors.json` holds two links of the origin `https://apassy-relay.wyderka.cc`, synthetic keys only:

- `anyone`: one secret, not one-time, access `anyone`.
- `one_time_emails`: a folder of two secrets, one of them in a subfolder, one-time, access `emails`, with two addresses.

Each link has its key, the link text, the link id, the seal key, the address key, the snapshot, the JSON length, the padded plaintext, the associated data, the nonce, the sealed form, its addresses with their normal forms and hashes, and the body of `POST /v1/account/links`. The list `addresses` holds texts with their normal form, or `null` when there is none. `generate_vectors.mjs` makes the file with WebCrypto in Node and gives the same file at each run.

## 10. Connect mail

Connect sends one kind of mail in this release: the code of section 4.5.

- From the sender of the relay (hosted: `connect@apassy.wyderka.cc`), to the address that the reader typed, in its normal form.
- Plain text, no link, no image, no tracking, no name of the person who made the link:

  ```text
  Subject: Your Apassy code

  Your code to open a shared Apassy item: 123456

  It works for 10 minutes. If you did not ask for it, ignore this mail.
  ```

- The relay writes the mail to an outbox in `links.db` and a sender hands it to the SMTP server of the operator (submission with TLS). A sent mail leaves the outbox at once; a mail that cannot be sent within one hour is deleted. The address is in the outbox only, never in a log.
- A relay without a mail sender has no `emails` links (section 4.1).

## 11. What Connect stores

| Where | What | How long |
| --- | --- | --- |
| `links.db`, link row | The link id, the account id, the times, the one-time flag, the access mode, `opens`, `last_opened_at`, the sealed form | Until the expiry, the revoke, or the account's deletion. A one-time link loses its sealed form and its address hashes at its open; its row stays until its expiry, for the list of section 4.2 |
| `links.db`, address hashes | The address hashes of a link of `emails` | With the link |
| `links.db`, codes | A hash of each code with the link id, the address hash, its expiry, and its tries | 10 minutes, or the fifth wrong try, or its use |
| `links.db`, outbox | The address and the text of a code mail | Until it is sent, at most 1 hour |
| Memory | The counts of section 7 | Their window |

`links.db` is not in the backups of the relay. Connect never stores `K`, the seal key, or a client address with a link id.

## 12. Reserved for release B

Release B of ADR 0047 (shares with a person) adds sections to this contract and changes none of sections 1 to 11. These names are reserved for it:

- Routes: `PUT /v1/account/email` and `POST /v1/account/email/verify` (the verified address of an account), `/v1/account/collections/…` (collections, the member log, invitations, sealed share keys, edit slots, edit requests, leave).
- Tags: `apassy-connect collection-log v1`, `apassy-connect share-accept v1`, `apassy-connect share-leave v1`, `apassy-connect share-edit v1`, `apassy-connect share-key v1`.
- Codes: `share_limit`, `email_required`, `email_mismatch`.
- The invitation mail: Connect sends it with the link of the invitation to the address that the sharer named; the person verifies that address on their account with a code before they accept.
- The normal form of section 6 is also the form of an account's address; the hash of release B is its own.
