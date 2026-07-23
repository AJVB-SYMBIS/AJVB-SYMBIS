# Security-scan — searchcompany.nl (+ subdomeinen)

> Uitgevoerd op **2026-07-23**, met expliciete toestemming van de opdrachtgever.
> Scope: de in de subdomeinscan gevonden hosts (`searchcompany.nl`, `www`, `ftp`,
> `mail`, `pop`, `smtp`). Aanpak: verantwoord en niet-destructief — TCP-connect
> checks, TLS-inspectie, HTTP-securityheaders en DNS/e-mail-hardening. Geen
> exploitatie, geen brute-force op inloggen, geen belastingtests.

## ⚠️ Belangrijke beperking van de meetomgeving

Alle uitgaande HTTP(S) uit deze scan-omgeving loopt **transparant door een
policy-enforcing egress-gateway** die TLS her-termineert. Het teruggekregen
TLS-certificaat was uitgegeven door `CN=Egress Gateway SDS Issuing CA, O=Anthropic`
— dus **niet** het echte certificaat van searchcompany.nl. Gevolg:

- De **poortscan** ziet alleen wat de gateway doorlaat (80/443) en zegt **niets**
  betrouwbaars over de werkelijk open poorten van de host.
- **TLS-versies, cipher en certificaat** van de host zijn van hieruit **niet**
  echt meetbaar.
- De IPv6-only servicehosts (`ftp/mail/pop/smtp`) zijn onbereikbaar (geen IPv6 in
  de omgeving).

De **netwerk-/TLS-laag is daarom niet vanuit deze omgeving beoordeeld.** Voor die
laag is een scan vanaf een normale internetverbinding nodig (bijv. `nmap`,
`testssl.sh`, SSL Labs). De **DNS- en e-maillaag hieronder is wél volledig
betrouwbaar** (directe DNS-resolutie, niet via de gateway).

## Bevindingen — DNS & e-mail (betrouwbaar)

| Onderdeel | Status | Bevinding |
|-----------|--------|-----------|
| **DNSSEC** | ✅ Sterk | Ingeschakeld — `DNSKEY` aanwezig én `DS` gepubliceerd bij de parent (`.nl`). Ketting van vertrouwen compleet. |
| **DKIM** | ✅ Goed | `google._domainkey` aanwezig met geldige RSA-sleutel (Google Workspace). |
| **AXFR (zone transfer)** | ✅ Goed | Alle 3 nameservers (`ns.zxcs.nl/.eu/.be`) weigeren AXFR. |
| **SPF** | ⚠️ Matig | `v=spf1 include:_spf.google.com ~all` — eindigt op **softfail (`~all`)**. |
| **DMARC** | ⚠️ Zwak | `v=DMARC1; p=none; sp=none;` — **alleen monitoring**, geen handhaving, én **geen `rua`** (er worden geen rapportages verzameld). |
| **CAA** | ⚠️ Ontbreekt | Geen CAA-record → **elke** CA mag een certificaat uitgeven voor het domein. |

### Correctie op de subdomeinscan
In het eerste rapport stond "geen DMARC/DKIM aangetroffen". Dat was een gevolg van
een beperkte resolver-check en is **onjuist**: beide records **bestaan wél**. De
juiste bevinding is dat ze bestaan maar **niet streng zijn afgesteld** (DMARC
`p=none`, SPF `~all`).

## Bevindingen — applicatielaag (indicatief)

- `www.searchcompany.nl` gaf op de scanverzoeken **HTTP 403** terug — de site
  (ZXCS-hosting/WAF) blokkeert vermoedelijk datacenter-/niet-browserverkeer. Dat
  is op zich een redelijke basisbescherming.
- Op de ontvangen respons waren **geen securityheaders** aanwezig
  (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy). Dit is gemeten op een 403-respons via de gateway en moet
  **op een normale 200-pagina vanuit een browser geverifieerd** worden voordat er
  conclusies aan verbonden worden.

## Aanbevelingen (prioriteit hoog → laag)

1. **DMARC aanscherpen.** Ga gefaseerd van `p=none` → `p=quarantine` → `p=reject`
   en voeg een `rua=mailto:…`-rapportageadres toe, zodat spoofing zichtbaar en
   uiteindelijk geblokkeerd wordt. Nu wordt vervalste mail namens het domein niet
   tegengehouden.
2. **SPF verstrengen** van `~all` naar `-all` zodra bevestigd is dat alle
   legitieme verzenders in het record staan (nu enkel Google).
3. **CAA-record toevoegen** (bijv. alleen de gebruikte CA toestaan) om
   ongeautoriseerde certificaatuitgifte te voorkomen.
4. **HTTP-securityheaders** op de webserver zetten (HSTS met preload, een
   passende CSP, X-Frame-Options/`frame-ancestors`, X-Content-Type-Options:
   nosniff, Referrer-Policy) — na verificatie op een echte pagina.
5. **Externe TLS-/poortscan** laten uitvoeren vanaf een normale verbinding
   (SSL Labs / `testssl.sh` / `nmap`) om de netwerklaag af te dekken die hier niet
   meetbaar was.

## Positieve punten

- DNSSEC volledig geïmplementeerd (sterk, relatief zeldzaam).
- Zone transfers correct geweigerd.
- DKIM aanwezig; mail uitbesteed aan Google Workspace.
- Geen exposed test-/admin-/staging-subdomeinen aangetroffen.
- Aanvalsoppervlak klein: één gedeelde webhost, mail bij Google.

## Reproduceren

Scripts staan in de sessie; kern voor de e-maillaag:

```python
import dns.resolver
r = dns.resolver.Resolver(); r.nameservers = ['8.8.8.8','1.1.1.1']
for name,typ in [("searchcompany.nl","TXT"),("_dmarc.searchcompany.nl","TXT"),
                 ("google._domainkey.searchcompany.nl","TXT"),
                 ("searchcompany.nl","DNSKEY"),("searchcompany.nl","DS"),
                 ("searchcompany.nl","CAA")]:
    try: print(name, typ, [x.to_text() for x in r.resolve(name, typ)])
    except Exception: print(name, typ, "MISSING")
```
