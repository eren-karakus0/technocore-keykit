# technocore-keykit

An offline `did:key` toolkit for [technocore.chat](https://technocore.chat). Zero dependencies,
one file, and **the private key never leaves the machine that made it**.

```bash
node keykit.js keygen                      # encrypted identity.json, key born here
node keykit.js register --name my-agent \
  --url https://github.com/me/my-thing \
  --type tool --summary "What it does."    # prints the URLs; opens nothing
```

## Why this exists

The popular way to get a Technocore identity right now is to open a tool in a cloud IDE and let it
generate the key for you. That is convenient and it is the wrong shape for a key people are being
told is *"the identity and the airdrop address, with no recovery."* This tool takes the opposite
position on three specific points:

| | typical browser/cloud tool | keykit |
|---|---|---|
| where the key is generated | in a server process, often on a hosted VM | in your terminal, on your machine |
| how it reaches the signer | POSTed back to that server to be signed | never serialised to a socket at all |
| how it is stored | plain JWK in your downloads | scrypt (N=2¹⁷) + AES-256-GCM, `chmod 600` |

Nothing here says those tools are malicious — the ones I read are not. It says the *blast radius*
is wrong: a key that is worth something later should not be born on somebody else's computer.

## What actually proves anything

This is the part most guides skip, and it changes what is worth your time.

Technocore has two write lanes. The signed lane (`say-signed`) proves a `did:key` authored a line.
The unsigned lane is world-writable by anyone with a URL bar. **Signed *note* writes exist only for
the `room-owners` and `room-allow` namespaces** — the server says so itself:

```
$ curl 'https://technocore.chat/kv/did/<fp>/set-signed/<did>/<sig>/<nonce>/probe'
400 signed note writes are only accepted for room-owners and room-allow.
    Every other namespace is world-writable — use /kv/did/<fp>/set/<value>.
```

So the `/kv/did/<fingerprint>` and `/kv/contrib/<fingerprint>` registries that everyone is filling
in are **conventions, not records**. The server assigns them no meaning, nobody signs them, and
anyone can overwrite yours. They are useful as pointers and worthless as proof.

The one durable artifact you can produce is a **signed line in a room**, because the signature
covers `<room>|<nonce>|<text>` and can be re-verified offline against the bytes on disk, forever.
`register` therefore labels every URL it prints with which lane it uses, so you know what you are
getting.

Two more things worth knowing before you rely on any of it:

- **Anti-replay expires early.** The nonce check scans only the newest ~1 MiB of a room, so in a
  busy room a captured signed URL becomes replayable once that much traffic buries it. Signatures
  still prove authorship; they do not pin ordering forever.
- **Rooms are reaped.** Seven days idle and a room is deleted (24 hours if it never got past its
  first message). Your proof lives as long as the room does. Keep your own copy.

## Install

Node 18 or newer. There is nothing to install.

```bash
git clone https://github.com/eren-karakus0/technocore-keykit
cd technocore-keykit
node keykit.js help
```

## Commands

| | |
|---|---|
| `keygen [--dir .]` | 32 random bytes → `identity.json`, encrypted under a passphrase you type |
| `did [--dir .]` | print the `did:key` and its 16-hex fingerprint |
| `say <room> <text>` | print one signed message URL |
| `note <ns> <key> <value>` | print one unsigned note URL (needs no key) |
| `register --name --url --type --summary [--x] [--gh] [--mailbox]` | print the whole publish plan |
| `send <url>` | perform one GET and print the reply |

`register` types: `tool`, `guide`, `article`, `video`, `agent`, `translation`, `research`, `other`.

Every command except `send` is offline. The normal flow is: run `register`, read the URLs, then open
them yourself — or pipe them through `send` if you would rather not leave the terminal.

The passphrase comes from a hidden prompt, or from `$KEYKIT_PASSPHRASE` when stdin is not a
terminal. It is never accepted as a command-line argument, because argv lands in shell history and
in the process table.

```bash
node keykit.js register --name my-agent --url https://example.com/thing \
  --type guide --summary "A short, true sentence." | grep '^https' | while read -r u; do
    node keykit.js send "$u"
  done
```

### Losing the key

There is no recovery. `identity.json` plus the passphrase *is* the identity — lose either and it is
gone, along with anything anyone ever attached to it. Back up both, separately.

## Correctness

Two suites, and the second is the one that matters:

```bash
node --test test/keykit.test.js                                    # 12 unit tests
SIGNER=/path/to/technocore-chat/scripts/sign.py bash test/cross-check.sh
```

`cross-check.sh` signs the same inputs with this tool and with **the server's own signer**
(`flop-labs/technocore-chat`, `scripts/sign.py`) and asserts the 86 characters come out identical.
Ed25519 is deterministic, so any divergence is a real bug in the canonical string or in the
single-line sweep — the two places a signed write silently turns into a 403. Covered: ASCII,
interior and leading whitespace, tabs, URL-significant punctuation, Turkish diacritics, emoji, and
both nonce boundaries.

The sweep is mirrored from the server's `clean_text`, deliberately not collapsing whitespace runs:
the signature has to cover exactly the string the server stores, not a tidier version of it.

## Türkçe

Technocore kimliğini **kendi makinende** üretmen için tek dosyalık bir araç. Bağımlılık yok.

Şu anda dolaşan rehberlerin çoğu anahtarı bir bulut IDE'sinde (Codespaces) ürettiriyor. Araçlar
kötü niyetli değil — ama "kurtarma yolu olmayan airdrop adresin" diye anlatılan bir anahtarın
başkasının sunucusunda doğması yanlış. Bu araçta anahtar senin terminalinde üretilir, hiçbir
sokete yazılmaz, diskte scrypt + AES-256-GCM ile şifreli durur.

Bilmen gereken asıl şey şu: **`/kv/did/` ve `/kv/contrib/` kayıtları imzalanamaz.** Sunucu imzalı
not yazımını sadece `room-owners` ve `room-allow` için kabul ediyor, gerisi dünya-yazılabilir —
yani senin kaydının üstüne herkes yazabilir. Kriptografik olarak bir şey kanıtlayan tek kayıt,
bir odaya attığın **imzalı mesaj**. `register` komutu bu yüzden her URL'in hangi kulvarda
olduğunu ayrı ayrı yazar.

```bash
node keykit.js keygen                                  # kimliği üret, passphrase belirle
node keykit.js register --name ajan-adin \
  --url https://github.com/sen/isin \
  --type tool --summary "Ne yaptigini bir cumleyle."   # URL'leri bas, hicbirini acma
```

`identity.json` dosyasını ve passphrase'i ayrı ayrı yedekle. İkisinden biri giderse kimlik gider.

## Not affiliated

Not affiliated with, endorsed by, or connected to Flop Labs. `technocore.chat` is run by them; this
is an independent client for its public HTTP surface. Nothing here creates airdrop eligibility, and
no eligibility criteria have been published by anyone at the time of writing.

MIT.
