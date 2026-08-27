# Kryptografický návrh

Tento dokument je specifikace formátu uloženého záznamu. **Formát je zamrzlý** —
změna kterékoliv konstanty nebo pořadí vstupů znehodnotí všechny živé secrety.
Testovací vektory v `internal/crypto/testdata/` jsou proti tomu pojistkou:
jakákoliv úprava odvození klíčů je okamžitě vidět jako rozbité vektory.

## Přehled

```
K          = 32 náhodných bajtů              ← žije POUZE v URL fragmentu
id         = base64url(SHA-256("onetime-id-v1" ‖ K))[:22]     ← klíč v Redisu
salt       = 16 náhodných bajtů              ← v Redisu
DEK        = 32 náhodných bajtů              ← nikdy se neukládá

bez hesla navíc:
  ikm = K ‖ masterKey[aktivníID]
s heslem navíc:
  pk  = Argon2id(heslo, salt ‖ masterKey, m=19456 KiB, t=2, p=1) → 32 B
  ikm = K ‖ pk ‖ masterKey[aktivníID]

KEK  = HKDF-SHA256(ikm, salt, info="onetime/v1/kek", 32 B)
wdek = AES-256-GCM(KEK, DEK, aad="onetime/v1|wrap|<id>|<keyID>")   ← v Redisu
data = AES-256-GCM-STREAM(DEK, plaintext)      ← v Redisu (krátký text) nebo na svazku
```

Odkaz pro příjemce je `https://<host>/s/<id>#<base64url(K)>`.

## Proč právě takhle

**Klíč je ve fragmentu, ne v cestě.** Fragment prohlížeč neposílá na server.
Nedostane se tedy do access logu ingressu, do `Referer`, ani do firemní proxy.
Zároveň z toho plyne anti-prefetch obrana: robot, který si odkaz otevře kvůli
náhledu, prostě nemá co odeslat.

**Klíč v Redisu je hash `K`, ne `K` samotné.** Referenční implementace používá
URL token přímo jako klíč záznamu, takže dump databáze plus globální secret
otevře všechny secrety bez hesla. Tady dump plus master klíč neotevře nic —
chybí `K`.

**Bez hesla navíc se nepoužívá pomalý KDF, a je to záměr.** `K` je 256 bitů
výstupu z CSPRNG; protahovat ho Argon2id nic nepřidá a jen by to dalo útočníkovi
levný způsob, jak nám spálit CPU na reveal endpointu. Heslo navíc je naopak
nízkoentropický lidský vstup, tam je Argon2id nutný.

**Sůl je svázaná s master klíčem** (`salt ‖ masterKey` jako sůl pro Argon2id).
Kdo ukradne databázi, ale ne master klíč, nemůže na heslo navíc spustit ani
offline slovníkový útok.

**Envelope šifrování** (náhodný DEK zabalený pod KEK) kupuje dvě věci. Ověření
hesla je rozbalení 32 bajtů — stojí stejně, ať je obsahem heslo nebo 50MB
soubor. A rotace master klíče vyžaduje přepsat jen 60bajtový obal, ne payload.

**Heslo navíc se neukládá vůbec, ani jako hash.** Ověřuje se tím, že sedí
autentizační tag při rozbalení DEK. V databázi tedy není žádný offline
lámatelný artefakt — na rozdíl od reference, která ukládá BCrypt hash. Cenou je,
že špatné heslo a poškozený záznam nejde rozlišit; hlásíme špatné heslo
a integritu hlídá metrika `onetime_decrypt_failures_total`.

## Formát payloadu (STREAM)

Jedna zpráva AES-GCM nemůže pokrýt 50 MB a nešlo by ji streamovat. Používáme
konstrukci STREAM (Hoang–Reyhanitabar–Rogaway), stejnou jako `age` a Tink:

```
hlavička:  "OTS1" (4 B) ‖ nonce_prefix (7 B)
chunk_i:   AES-256-GCM(DEK,
             nonce = nonce_prefix(7) ‖ counter_be32(4) ‖ final_flag(1),
             plaintext_chunk (64 KiB, poslední může být kratší),
             aad = "onetime/v1|payload|<id>|<keyID>")
```

- **Counter v nonce** → přeházení ani zopakování chunků nelze provést nepozorovaně.
- **Final flag na posledním chunku** → useknutí souboru je detekovatelné. Bez něj
  by útočník mohl soubor tiše zkrátit a příjemce by to nepoznal.
- Writer bez `Close()` vyprodukuje data, která reader **odmítne** — tichá
  ztráta konce souboru je horší než hlasitá chyba.

Stejný formát se používá pro krátký text v Redisu i pro soubory na svazku, takže
existuje jedna cesta, kterou je potřeba otestovat.

## Co je kde

| Artefakt | URL | Redis | Svazek | k8s Secret | RAM |
|---|:-:|:-:|:-:|:-:|:-:|
| `K` (klíč secretu) | ✅ fragment | ❌ (jen SHA-256) | ❌ | ❌ | po dobu requestu |
| klíč účtenky | ✅ fragment | ❌ (jen SHA-256) | ❌ | ❌ | po dobu requestu |
| `salt` | ❌ | ✅ | ❌ | ❌ | |
| `wdek` | ❌ | ✅ | ❌ | ❌ | |
| `DEK` | ❌ | ❌ | ❌ | ❌ | ✅ jen v RAM |
| master keyring | ❌ | ❌ | ❌ | ✅ | ✅ |
| ciphertext (text) | ❌ | ✅ | ❌ | ❌ | |
| ciphertext (soubor) | ❌ | ❌ | ✅ | ❌ | |
| jméno souboru | ❌ | ✅ **šifrovaně** | ❌ | ❌ | |
| heslo navíc (ani hash) | ❌ | ❌ | ❌ | ❌ | po dobu requestu |

Vlastnosti, které z toho plynou:

- Dump Redisu **+** master klíč ⇒ **nedešifruje nic** (chybí `K`).
- Dump Redisu + jeden odkaz ⇒ potřebujete ještě master klíč z k8s Secretu.
- Všechno tři + secret má heslo navíc ⇒ zbývá Argon2id brute-force per secret.
- Krádež svazku bez Redisu ⇒ jen ciphertexty bez obalů, tedy nic.

## Download ticket

Soubor se spálí v okamžiku odhalení, ale stahování 50 MB může selhat v půlce.
Reveal proto vrátí ticket = `16 B náhodných ‖ 32 B DEK`, base64url. **DEK je
uvnitř ticketu, ne v Redisu** — dump databáze během těch pěti minut je pořád
bezcenný. V Redisu je pod `SHA-256(nonce)` jen odkaz na soubor, zašifrované
jméno a AAD. Povolený počet pokusů je omezený (default 3), aby se z ticketu
nestala trvalá stahovací URL.

## Rotace master klíče

Keyring, ne jedna hodnota:

```
ONETIME_MASTER_KEYS="v2:<base64-32B>,v1:<base64-32B>"
```

První položka je aktivní pro zápis, ostatní slouží ke čtení starších záznamů.
Každý záznam si pamatuje `keyID`, pod kterým vznikl.

Postup je v [`RUNBOOK.md`](RUNBOOK.md). Nejdůležitější pravidlo: **starou položku
odstraňte teprve až vyprší všechny secrety pod ní zapsané.** Odstranění dřív
znamená, že se ty záznamy staly natrvalo nečitelnými — aplikace to zvládne
gracefully (vrátí „odkaz už není platný", ne 500), ale data jsou pryč.

## Co tenhle návrh neřeší

Poctivý výčet, protože předstírat stoprocentní ochranu je horší než ji nemít:

- **Server vidí plaintext v okamžiku vytvoření a odhalení.** Plná
  zero-knowledge architektura (šifrování v prohlížeči přes WebCrypto) by tohle
  odstranila, ale rozbila by primární požadavek: agent v curl one-lineru nemá
  jak dělat client-side kryptografii, a 50MB soubor by přes WebCrypto vyžadoval
  Service Worker, který padá za korporátními proxy. Pole `alg` v záznamu nechává
  dveře otevřené pro pozdější E2EE mód u textových secretů.
- **Kdo má odkaz, má obsah.** Proto heslo navíc jako druhý faktor — a proto
  doporučení posílat odkaz a heslo dvěma různými kanály.
- **TLS interception** na firemní proxy vidí tělo requestu. Krátká expirace
  a jednorázové čtení omezují okno, `secret.revealed` v logu dá důkaz o přečtení.
- **Náhledoví roboti** jsou blokovaní na několika vrstvách, ale u opravdu
  citlivých věcí je bezpečnější předpokládat, že obsah mohl vidět i někdo další.
  UI to uživateli říká otevřeně.
