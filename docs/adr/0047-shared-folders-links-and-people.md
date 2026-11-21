# ADR 0047 — Shared folders, public links, and shares with a person by e-mail address

Status: Accepted by the owner on 2026-11-21, in two releases. Release A (schema 35, a secret in
several folders, public links) is frozen for implementation; contract
[connect-share-v1](../contracts/connect-share-v1.md). Release B (shares with a person) is decided
here and gets its contract sections later. Not built.
Date: 2026-11-21

The owner asked for three things. Share folders with people outside the family or team, with one
secret in several folders. A public secret that anyone reads without a Connect account. A share to an
e-mail address that shows in the other person's app until it is revoked, with edit rights for up to
10 secrets on Personal and Family and without a limit on Team.

## Context

- A credential is in at most one folder (`item_folder`, schema 18, ADR 0026 §5).
- Since 0.5.20 two accounts of one family or team share a whole vault (contract connect-account-v1
  section 16). Both need a plan. The other person needs the passphrase of the vault.
- ADR 0014 §7 planned a shared collection with its own file and its own key. It is not built. The
  tables `shared_vault`, `item_share`, and `item_home` of ADR 0026 §6 are in the schema and no code
  fills them.
- A device refuses a signed device list that holds an entry it does not know. So a new kind of entry
  in that list would stop every device of 0.5.20 that reads it.
- A device list holds 1024 entries over its life, and at most 64 peers and 128 shares and joins.
- A Connect account has no e-mail address that Connect verified. Connect sends no mail.
- ADR 0037 §1: no Apassy-run server holds a key that opens a credential.

## Decision

### 1. Rules

1. A secret is one credential in one vault, the vault of the person who shares it. Folders, links,
   and shares point at it. Nothing copies it inside that vault.
2. Connect keeps ciphertext, signed entries, hashes, and counts. It never keeps a key that opens a
   secret. It learns an e-mail address only to send a mail to it: the address of a link reader who
   asks for a code (release A), and the addresses of an invitation and of an account (release B).
3. Only the devices of the sharing account write a shared folder. A change by another person is a
   signed request. A device of the sharer applies it.
4. Connect can end a share. It cannot start one: only a device of the sharer signs a member entry and
   seals the share key. Which key a person has rests on Connect and the person's verified address
   (section 5.3).
5. A step that gives a person a secret needs a fresh owner check. The "How often to ask" window never
   covers it. A step that takes access away needs none.
6. A relay that you run yourself has no plan limits (ADR 0037 D3).
7. No existing route, answer, or signed list changes. Everything here is new routes, new tags, and
   new tables.

### 2. A secret in several folders (release A)

- Schema 35 gives `item_folder` the key `(item_id, folder_uuid)` and the column `added_at`. A
  credential is in any number of folders, or in none.
- It stays a child row of the credential. The content hash of a credential with no folder or one
  folder is the hash of schema 34, so a copy of schema 34 merges without a conflict. Two or more
  folders add a part `v35` with the sorted UUIDs.
- Each membership is a row with its own version and a tombstone when it ends, and it merges on
  its own: the later of the add and the removal wins (contract vault-v1, schema 35). Concurrent
  moves from "Work" to "Home" and from "Work" to "Bills" leave the credential in both.
- Release B: a removal from a shared folder must win over a concurrent add, so that a secret
  leaves a share when the owner takes it out; the later version alone does not ensure that.
- "Move to Folder…" replaces the folder of the list the owner is in. "Add to Folder…" adds one.
  "Remove from This Folder" removes one. Deleting a folder still deletes no credential.
- The catalog of an agent keeps `folder` (the first path, by `added_at`) and gets `more_folders`
  when there are more.

### 3. What a person can share

- A public link (release A): a folder with its subfolders, or one secret.
- A share with a person (release B): the same, as a **collection**.
- A folder inside a shared folder is not shared again, and a folder that holds a shared folder is not
  shared.
- A link and a collection never hold: an archived credential, a passkey field, a short-lived
  credential, a member key, the history, "Always ask me", or the folders outside the shared folder. A
  link also holds no one-time-code seed; a collection holds code seeds.
- A secret that the person received from someone else is never in a collection or a public link of
  theirs.
- A secret enters a shared folder only by the owner's action with the owner check. An agent's new
  credential that would land in a shared folder goes to the top level, and the answer says so. The
  iPhone refuses the move and names the Mac.

### 4. The public link (release A)

- **Who:** every Connect account, also an account without a plan. The limits are in section 6.
- The Mac or Linux computer makes a key `K` of 32 random bytes and a snapshot of the secret or
  folder: names, fields, notes.
- `link_id` is the first 16 bytes of HKDF-SHA256 of `K`. The snapshot is JSON, padded to a multiple
  of 1024 bytes, sealed with AES-256-GCM under a second HKDF key. The associated data binds the
  origin, the id, the expiry, the one-time flag, and the access mode. The plaintext is at most 32 KiB.
- The link is `<Connect origin>/s#v1.<K>`. The key is only in the fragment. No server gets it. The
  origin is `https:` (`http://localhost` and `http://127.0.0.1` only for tests); the app makes no link
  for another origin. A new content always gets a new `K`, and Connect stores each link id once: a
  tombstone of every id it ever stored refuses its reuse.
- **Two access modes**, as in 1Password:
  - "Anyone with the link".
  - "Only these e-mail addresses". The sharer names 1 to 20 addresses. Connect keeps only their
    hashes, under a key that comes from `K`. The viewer asks for the reader's address; Connect checks
    it against the hashes and mails a one-time code of 8 digits to it; only after the code does
    Connect give the sealed form. Connect answers a code request before it looks at the address, so
    the answer is the same whether or not the address is on the link. A pair of link and address has
    10 wrong tries over the life of the link and 5 codes a day; each sharing account has a daily cap
    of code mails (50, or 200 on Team).
- Connect keeps the sealed form in `links.db`, a file of its own that is not in the backups. A link
  that expired or was revoked is deleted there, and no backup brings it back.
- The page `/s` is one static page with one script and one style file. It reads the fragment, takes
  it out of the address bar, asks before it opens a one-time link, fetches with
  `POST /v1/links/{id}/open`, and decrypts with WebCrypto. It loads nothing from another origin, and
  its Content-Security-Policy allows nothing else. Unknown, expired, revoked, and already opened links
  give one answer, 404.
- Expiry: 10 minutes to 30 days, 7 days by default. "Show once" deletes the sealed form in the
  transaction of the first open. Connect counts opens and keeps no reader address.
- The link is a snapshot. A later change of the secret does not reach it.
- Creating a link needs the owner check `CreatePublicLink`, which names the secrets, the expiry, the
  one-time flag, the access mode, and the addresses. Revoking needs none. The vault keeps each link
  in `public_link` (synced), so every device of the owner lists, copies, and revokes it.
- **No other script of the origin.** Whoever serves a script at the link's origin can read `K`. So
  a relay that serves links registers no service worker (it refuses every request with
  `Service-Worker: script`), and the answers of its agent proxy `/p/` run sandboxed, in an opaque
  origin. It never redirects `/s`.
- The app checks the size of the snapshot (32 KiB) before the owner check and says how many of the
  chosen secrets fit.
- **For a secret that matters** the app recommends "Show once" or "Only these e-mail addresses": a
  plain link stays readable for whoever finds it until it ends (section "What this does not protect").
- A relay that you run yourself serves the same page and routes. The link works where that relay is
  reachable. "Only these e-mail addresses" needs a mail sender on that relay.

### 5. A share with a person (release B)

#### 5.1 The collection at Connect

- A collection is a relay-sync-v1 store of a new kind, `collection`, made by the sharing account. It
  is not in the answers about vault stores.
- Its copy is a SQLCipher file with a random key of 32 bytes, the share key. It holds the folder
  rows, the credentials with their fields, tags, declaration, variable and connector, and their
  folders inside the collection.
- Every head is signed by a device of the sharing account. Connect takes a push only from such a
  device. A recipient's device verifies the head from the sharer's root and imports the copy. It
  never signs one.
- A sharer device never writes an older version of a credential over a newer one. It compares the
  clock of each record with the copy at Connect before it pushes.

#### 5.2 The member log

Each collection has a signed log at Connect. The account device list stays as it is.

| Entry | Meaning |
| --- | --- |
| `open` | This account made the collection. Version 1. |
| `read P R h` | The account P with the root R reads it. `h` is the hash of P's answer. |
| `edit P R h` | P reads it and sends edit requests. |
| `end P` | P's access ended. |
| `close` | The collection ended. |

Each entry is signed by a device of the sharer's list over `"apassy-connect collection-log v1"`, the
origin, the account, the store, the version, the hash of the entry before, and its fields. A device
keeps the newest version it verified and takes no older one and no fork.

#### 5.3 The invitation, by e-mail as in 1Password

1. The sharer picks the folder or the secret, a person, and Read or Edit. The person is a member of
   the family or team, or an e-mail address.
2. The sharer's device gives Connect the address, the role, and the expiry (14 days). **Connect sends
   the invitation mail** with the link of the invitation to that address.
3. The person verifies that address on their Connect account with a code that Connect mails to it.
   Connect takes an answer to an invitation only from an account whose verified address is the
   address of the invitation.
4. The person accepts in Settings › Connect. Their device signs an answer over
   `"apassy-connect share-accept v1"` with its root, its key, and a new P-256 receive key.
5. **No six words.** The trust anchor for the person's receive key is Connect and the verified
   address. The sharer's app shows the address and the short fingerprint of the person's root; a
   comparison is possible and never required.
6. The sharer's confirmation is the owner check `ShareWithPerson`. It names the person, the folder,
   the count of secrets, and the role. The device then signs the `read` or `edit` entry, seals the
   share key to the receive key (ephemeral P-256 ECDH, HKDF-SHA256, AES-256-GCM, bound to the store
   and both accounts), and adds the person's device to the store.
7. The person's device opens the key, downloads the copy, and imports it.

A person whom the sharer shared with before needs no new invitation: Connect shows them the offer by
account, they accept, and the sharer confirms with the owner check. Any Mac or Linux computer of the
sharer can confirm: the share key syncs with the vault.

#### 5.4 The e-mail address of an account

- An address is optional. A person needs it only to accept an invitation.
- `PUT /v1/account/email` sends a code of 8 digits to the address. The code lives 15 minutes and takes 5
  tries. One verified address for each account. An address that another account verified later moves
  to that account.
- Connect sends this mail, the invitation mail, and the code mail of a public link (section 4). Each
  is plain text. The code mails hold no link. The relay hands them to an SMTP server from an outbox.
  Without an SMTP server the address routes are off, and a share with a person needs a member of the
  family or team.

#### 5.5 Read and edit

- A reader's app shows the secrets and refuses a change.
- An editor changes the name, the fields, the notes, and the tags. Everything else of a shared secret
  is the sharer's.
- An edit is sealed under the share key and signed by the editor's device over
  `"apassy-connect share-edit v1"`. Connect takes it only from an account with an active `edit`
  entry, and only for a secret that the sharer registered for edits.
- A device of the sharer verifies the signature from the root in the log, applies the change to the
  one credential in the vault, keeps the value before the change, writes "Changed by <name>" in the
  history, and pushes a new copy.
- Until then the editor's app shows the new value with "Waiting for <name>'s device". The next copy
  from the sharer replaces it.
- An editor adds no secret to the folder and removes none.

#### 5.6 The end of a share

- "Stop Sharing with <name>…" signs `end P`. Connect removes P's devices from the store in the same
  transaction, with the sealed key and P's waiting edits.
- The sharer's device then makes a new share key, pushes the copy under it, and seals it to each
  person who stays.
- "Leave…" on the other side signs a leave. Connect removes that person's devices at once. The
  sharer's device signs `end P` at its next refresh.
- The other person's app removes the secrets when it has verified the `end` entry. The removal syncs
  to their other devices. A refusal or an error of Connect removes nothing.
- A secret that stays in another collection for the same person stays.
- The sharer then sees which secrets the person had, with "Change these if they matter". The mark
  goes when the value changes.
- When the sharer's plan ends, the collection is read-only, then not served, then deleted, as a vault
  store is. The other person keeps the last copy with "No longer updated".

### 6. Plans and limits

| | No plan | Personal | Family, each person | Team, each member | Own relay |
| --- | --- | --- | --- | --- | --- |
| Public links, live at once (A) | 25 | 25 | 25 | 100 | no limit |
| Longest life of a public link (A) | 30 days | 30 days | 30 days | 30 days | 30 days |
| Receive a share, read (B) | yes | yes | yes | yes | yes |
| Edit a received secret, when the sharer gave edit rights (B) | yes | yes | yes | yes | yes |
| Share with people (B) | no | yes | yes | yes | yes |
| Secrets with edit rights, counted once each (B) | – | 10 | 10 | no limit | no limit |

The 10, the "no limit" of Team, the 25 and 100 links, and the 30 days are the owner's. Read-only
shares have only technical caps (collections of an account, people in one collection), settings of
Connect that release B names. The plan of the sharer pays and its limit counts: a person without a
plan may edit when the sharer gave edit rights.

Where each limit is checked:

- **The app** counts before the owner check and says what to do: revoke a link, share read-only,
  take edit rights from another folder, or change the plan. The iPhone names no plan change.
- **Connect** counts links, collections, and members in the transaction that adds one. For edit rights
  the sharer's device registers one slot for each secret: the SHA-256 of a tag and the UUID of the
  credential. Connect counts the distinct slots of the account. It takes an edit only for a
  registered slot. While an account holds more slots than its plan allows, Connect takes no edit for
  any of its collections.
- Connect cannot read a collection. A changed client can register fewer slots than it shares. It then
  gets no edits for the others.

### 7. The vault sharing of a family or team

- It stays as it is: a whole vault, between two accounts of one group, both on a plan, with the
  passphrase.
- A collection is a second way and works for anyone, also inside a group. The picker lists the group
  first. An address is needed only for a person outside.
- A removal from the group ends the shared vaults, as today. It ends no collection. The sharer's app
  says "<name> left your team. You still share 2 folders with them." with "Stop Sharing…".
- `shared_vault`, `item_share`, and `item_home` stay unused for the team host of ADR 0037 stage 4.

### 8. Agents

- A received secret is an ordinary credential with the mark `item_received`. The bouncer, runs, the
  catalog, the extension, and the iPhone need no second path.
- It starts with "Always ask me" on. Turning it off needs the owner check, as for any credential.
- The names that another person chose are never context for the bouncer. The folder of a received
  secret counts for no project fit.
- The catalog shows it under `["Shared with me", <share>, …]` with `shared_by` and `read_only`.
- An agent changes only credentials that it made, so it changes no received secret.
- Each received share has "Hide from Agents".
- An agent makes no public link and no share.

### 9. The apps

- **Mac and Linux.** "Share…" on a folder and on a secret opens one sheet: Public Link ("Create
  Link…", the access mode and the addresses, Copy, Revoke, the count of opens; release A) and People
  (the person, Read or Edit, the state, "Add Person…", "Stop Sharing…"; release B). A shared folder
  has a sign in the sidebar. The section "Shared" lists what others share with this person (B).
  Settings › Connect gets one list of every link (A), the address row and every share (B).
- **iPhone.** Display: every folder of a secret (A); "Shared by <name>", "Shared with N people" (B). A
  received secret is read-only there. No share and no link is made there.
- **Extension.** A suggestion of a received login says "Shared by <name>". A read-only login offers
  no update (B).
- **Site.** Pricing, privacy, and terms name the links, the mail, and the limits (A); the address and
  the invitation (B).
- **Apple Watch.** No change.

### 10. Releases

Two releases of all six components.

- A: schema 35, several folders, public links with both access modes, the Connect mail sender and
  the code mail of a link.
- B: schema 36, the account address, the invitation mail, collections, people, edit requests.

## Alternatives refused

- **New entries in the device list** (`read`, a store of a new kind). A device of 0.5.20 refuses the
  whole list, and every share would use the list's lifetime budget.
- **Every member writes the store**, as for a shared vault. Connect could not count secrets with edit
  rights, each device would need a merge that knows roles, and an editor could add and remove secrets
  for the others.
- **The version-vector merge on the share copy.** With one writing account it is not needed, and it
  would change the most delicate code of the sync.
- **A separate vault file for each shared folder.** A secret in two shared folders would be two
  credentials.
- **The sharer sends the invitation link, and six words are compared** (the draft of this ADR). The
  owner chose the e-mail flow of 1Password: fewer steps for the other person, at the cost of trusting
  Connect and the verified address for the first key (section "What this does not protect").
- **Public links only for paid plans** (the draft). The owner chose links for every account, with the
  same 25 for no plan, Personal, and Family.
- **Sealing to the account device key.** That key only signs (`src/connect/device_key.rs`).
- **A link that follows changes.** A leaked link would also leak the next value.
- **The viewer on the website's domain.** The relay would need CORS, and a relay that you run
  yourself would need a second copy.
- **Links in `relay.db`.** A backup would keep a link past its end.
- **Plain SHA-256 address hashes for a link.** Anyone with `links.db` could test addresses against
  them. A key from `K` makes the hashes of each link its own.
- **A mail provider's HTTP API in the relay.** A relay that you run yourself could not use its own
  server.

## Consequences

- Every device of a vault must run the build of schema 35 before it syncs again, and again for
  schema 36.
- Connect sends mail from release A: a sending identity (`connect@apassy.wyderka.cc`) with SPF and
  DKIM records, through the mail server of the operator. The privacy text, the terms, and the
  sentence "no password and no email" change.
- Connect holds, for a link of "Only these e-mail addresses", the keyed hashes of its addresses, and
  for at most one hour the address of a code mail. From release B it holds verified account
  addresses and invitation addresses.
- A change by an editor, and the confirmation of a new person, wait for a Mac or Linux computer of
  the sharer with the vault unlocked.
- The iPhone gets shared secrets through the vault sync of that person's Mac. A person with only an
  iPhone cannot accept a share in this version.
- Sharer, recipient, and link reader use the same Connect origin.
- Accounts without a plan become common. The caps for new accounts need a new look.
- The Connect origin serves no script but the viewer's: no service worker, and the agent proxy `/p/`
  only sandboxed.
- Hard to undo: the schema steps, the link format while links live, the signed formats once logs
  exist at Connect, the stored addresses, and the published limits.

## What this does not protect

- A person keeps what they saw or copied. An end removes the secrets from a cooperating app at its
  next sync. Change a secret that matters.
- Anyone with a public link of "Anyone with the link" reads the secret until the link ends. A link
  leaves copies where it travels: the browser's global history and the sync of that history (the
  viewer takes the key out of the address bar, but the browser may have written the whole link
  before), and the link rewriters and scanners of mail and chat services, which keep or open the
  links in a message. For a secret that matters, use "Show once" (a scanner that opens the page does
  not say yes) or "Only these e-mail addresses".
- Whoever serves `/share.js` at the link's origin can read `K` and the secret: the operator of
  Connect, its edge, or whoever controls the origin. The page is open source, and section 4 keeps
  other scripts of the origin out, but a reader's browser runs the script that the origin serves at
  that moment.
- "Only these e-mail addresses" is a check of Connect. A Connect that does not keep its rules can give
  the sealed form to anyone who has the link. Without the link it opens nothing.
- Whoever controls a named address (its mail account or its domain) can open a link of that address
  or accept an invitation to it.
- At the first share with a person, a Connect that lies can give the sharer a receive key of its own
  and read that collection. Comparing the fingerprint of the person's root finds this; the app does
  not require it.
- Connect can withhold the newest entries of a log, or keep devices apart. A person whose `end` entry
  Connect withholds keeps the last copy and gets no newer one.
- A person who reads a collection sees the device list of the sharer, and the account ids of the
  others in that collection. No name and no address.
- An editor can change a secret to a wrong value. The sharer's vault keeps the value before it.
- The name and the plain fields of a received secret are another person's text. An agent sees them in
  the catalog.

## Relation to other records

- ADR 0014 §7: the shared collection is built in release B, as a copy that one account writes.
- ADR 0026 §5 "at most one folder" is replaced by section 2. ADR 0026 §6 "only the item's owner edits
  it" is replaced by section 5.5. "One home, many shares" holds.
- ADR 0037 §1, D2, D3: Connect never holds a key that opens a secret, and the limits are Connect's
  only. Section 5.3 states what Connect is trusted for in release B.
- ADR 0046 rule 4: loosening needs the owner check.
- Contract connect-account-v1 section 16 does not change. The new wire is connect-share-v1.
