# Subdomeinscan — searchcompany.nl

> Passieve/niet-intrusieve reconnaissance. Uitgevoerd op **2026-07-23**.
> Methode: DNS-resolutie (Google/Cloudflare resolvers) + brute-force op een lijst
> van ~250 veelvoorkomende subdomeinnamen. Er is **geen** actief verkeer naar de
> webserver of poortscan uitgevoerd — enkel DNS-lookups.

## Samenvatting

`searchcompany.nl` (The Search Company — recruitment/executive search, Eindhoven)
draait op **Nederlandse shared hosting van ZXCS.nl** (`web0082.zxcs.nl`).
E-mail loopt via **Google Workspace**. Er zijn **5 subdomeinen** gevonden; allemaal
standaard-servicerecords van de hostingomgeving. Er zijn geen aparte
staging-, admin-, api- of applicatieomgevingen op eigen (sub)domeinen aangetroffen.

## Apex-records (`searchcompany.nl`)

| Type | Waarde |
|------|--------|
| A    | `185.104.29.12` (→ `web0082.zxcs.nl`, ZXCS shared hosting) |
| AAAA | `2a06:2ec0:1::82` |
| NS   | `ns.zxcs.nl`, `ns.zxcs.eu`, `ns.zxcs.be` |
| MX   | `ASPMX.L.GOOGLE.COM` + `ALT1..4.ASPMX.L.GOOGLE.COM` (Google Workspace) |
| TXT  | `v=spf1 include:_spf.google.com ~all` |
| TXT  | `google-site-verification=0MPMHNAEixVD4Tdjikfzbh0fBJbtZztHTy7k8HoQH90` |
| TXT  | `google-site-verification=zPZOFg-93TMZq84_y0XA0xWoVtsanDdIMRTwNM7hmcc` |
| SOA  | `ns.zxcs.nl hostmaster.searchcompany.nl` (serial 2026071604) |

## Gevonden subdomeinen

| Subdomein | A | AAAA | Opmerking |
|-----------|---|------|-----------|
| `www.searchcompany.nl`  | `185.104.29.12` | `2a06:2ec0:1::82` | Publieke website (zelfde host als apex) |
| `ftp.searchcompany.nl`  | — | `2a06:2ec0:1::82` | Standaard FTP-servicerecord hosting |
| `mail.searchcompany.nl` | — | `2a06:2ec0:1::82` | Webmail/mailrouting hostingpaneel |
| `pop.searchcompany.nl`  | — | `2a06:2ec0:1::82` | POP3-endpoint hostingpaneel |
| `smtp.searchcompany.nl` | — | `2a06:2ec0:1::82` | SMTP-endpoint hostingpaneel |

De records `ftp`, `mail`, `pop` en `smtp` zijn de gebruikelijke, automatisch
aangemaakte service-hostnames van het hostingpaneel (cPanel/DirectAdmin-stijl) en
verwijzen alle naar hetzelfde IPv6-adres als het apex-domein.

## Observaties

- **Één webserver, gedeeld IP.** De site staat op een gedeeld hosting-IP; er is
  geen eigen infrastructuur of CDN in gebruik.
- **Mail is uitbesteed aan Google.** MX en SPF wijzen naar Google Workspace.
  Let op: het SPF-record eindigt op `~all` (softfail) i.p.v. `-all` (hardfail).
  DMARC en DKIM bestaan wél (zie de aparte security-scan), maar zijn niet streng
  afgesteld (DMARC `p=none`) — aandachtspunt voor e-mailspoofing-weerbaarheid.
  > Zie `searchcompany.nl-securityscan.md` voor de volledige e-mail/DNS-analyse.
- **Geen zichtbare test-/acceptatieomgevingen** op subdomeinen. Dat is positief
  vanuit blootstelling-oogpunt (geen `staging.`, `dev.`, `admin.` gevonden).

## Beperkingen van deze scan

- Certificate Transparency-bronnen (crt.sh) waren vanuit deze omgeving
  geblokkeerd door het egress-beleid; de dekking leunt daarom op DNS-brute-force.
  Een aanvullende CT-check via crt.sh / Censys kan eventuele historische of
  wildcard-subdomeinen aan het licht brengen die niet in de woordenlijst zaten.
- Er is geen wildcard-DNS actief (gecontroleerd met een willekeurige hostnaam),
  dus de gevonden records zijn echt en geen false positives.

## Reproduceren

De gebruikte scripts staan in dit rapportmapje-proces; kern:

```python
import dns.resolver
r = dns.resolver.Resolver()
r.nameservers = ['8.8.8.8', '1.1.1.1']
for rt in ["A","AAAA","NS","MX","TXT","SOA"]:
    try: print(rt, [x.to_text() for x in r.resolve("searchcompany.nl", rt)])
    except Exception: pass
# + brute-force van "<woord>.searchcompany.nl" over een wordlist met A/AAAA-checks
```
