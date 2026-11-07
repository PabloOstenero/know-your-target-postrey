

Aquí tienes el informe de reconocimiento pasivo de `*.airbnb.com`:

---

# Informe de Reconocimiento Pasivo — *.airbnb.com

## ⚠️ Nota sobre el alcance

El alcance autorizado `*.airbnb.com` **no incluye el dominio raíz** `airbnb.com`. Todas las consultas sobre `airbnb.com` retornaron `BLOQUEADO`. El reconocimiento se ha realizado sobre el subdominio `www.airbnb.com` como representante del alcance.

---

## 1. Registro WHOIS

- **airbnb.com**: BLOQUEADO (fuera del alcance `*.airbnb.com`)
- **www.airbnb.com**: ERROR — Whois no respondió (Network unreachable), RDAP HTTP 404 *(whois_dominio)*

---

## 2. Registros DNS

### A (IPv4) — www.airbnb.com *(dns_registros)*

| Tipo | Valor |
|------|-------|
| CNAME (intermedio) | `airbnb-web.production.global.product.origins.airbnb.net.` |
| CNAME (Akamai) | `san.airbnb.com.edgekey.net.` |
| CNAME (Akamai) | `e118243.a.akamaiedge.net.` |
| IP | `96.16.88.147` |
| IP | `96.16.88.146` |
| IP | `96.16.88.144` |
| IP | `96.16.88.135` |
| IP | `96.16.88.153` |
| IP | `96.16.88.134` |
| IP | `96.16.88.137` |
| IP | `96.16.88.132` |
| IP | `96.16.88.151` |

→ **Infraestructura**: CDN de **Akamai** con balanceo entre 9 IPs en el rango `96.16.88.0/24`.

### Otros registros DNS (MX, NS, TXT, SOA, AAAA)

BLOQUEADO — `airbnb.com` está fuera del alcance autorizado *(dns_registros)*

---

## 3. Subdominios

### crt.sh (transparencia de certificados) *(subdominios_crtsh)*

- **1 subdominio en alcance**: `www.airbnb.com`
- 28 filtrados por estar fuera del alcance

### subfinder (fuentes pasivas) *(subdominios_subfinder)*

- No encontró subdominios para `www.airbnb.com`

### DNSDumpster *(subdominios_dnsdumpster)*

- ERROR — falta `DNSDUMPSTER_API_KEY` en el entorno

### Netcraft *(subdominios_netcraft)*

- BLOQUEADO — `airbnb.com` fuera del alcance

---

## 4. Infraestructura y puertos (InternetDB de Shodan) *(internetdb)*

| IP | Puertos | Hostname | Tags |
|----|---------|----------|------|
| `96.16.88.132` | 80, 443 | `a96-16-88-132.deploy.static.akamaitechnologies.com` | cdn |
| `96.16.88.134` | 80 | `a96-16-88-134.deploy.static.akamaitechnologies.com` | cdn |
| `96.16.88.136` | 80, 443 | `a96-16-88-136.deploy.static.akamaitechnologies.com` | cdn |
| `96.16.88.137` | 80, 443 | `a96-16-88-137.deploy.static.akamaitechnologies.com` | cdn |
| `96.16.88.143` | 80 | `a96-16-88-143.deploy.static.akamaitechnologies.com` | cdn |

- **Servicios**: HTTP (80) y HTTPS (443)
- **Tags**: CDN (Akamai)
- **CPEs**: Sin identificar
- **CVEs conocidos**: Ninguno reportado

---

## 5. Historial web (Wayback Machine) *(wayback_urls)*

- **4 992 URLs** en alcance para `www.airbnb.com`
- **132 URLs de interés**, incluyendo:

| Endpoint | Descripción |
|----------|-------------|
| `.well-known/amphtml/apikey.pub` | Clave pública AMP |
| `.well-known/assetlinks.json` | Digital Asset Links (Android/Google) |
| `.well-known/gpc.json` | Global Privacy Control |
| `.well-known/openid-configuration` | Configuración OpenID Connect |
| URLs con `?af=...&c=...&gclid=...` | Tracking de campañas de marketing/advertising |

---

## 6. Correos corporativos

- **theHarvester**: BLOQUEADO *(correos_theharvester)*
- **Hunter.io**: ERROR — falta `HUNTER_API_KEY` *(correos_hunter)*

---

## 7. Shodan API

- **shodan_host**: ERROR — falta `SHODAN_API_KEY` en el entorno

---

## Resumen ejecutivo

| Área | Hallazgo |
|------|----------|
| **CDN** | Akamai (9 IPs en `96.16.88.0/24`) |
| **Puertos expuestos** | 80, 443 |
| **Endpoints sensibles** | `.well-known/` (OpenID, Digital Asset Links, AMP, GPC) |
| **Subdominios identificados** | `www.airbnb.com` (1 en alcance crt.sh) |
| **Vulnerabilidades** | Ninguna reportada en InternetDB |
| **Vendors identificados** | Akamai (CDN), origin `airbnb.net` |

### Limitaciones del análisis

1. **Alcance `*.airbnb.com`**: Excluye el dominio raíz `airbnb.com`, bloqueando la mayoría de consultas WHOIS y DNS directas.
2. **APIs no configuradas**: DNSDumpster, Shodan y Hunter no funcionaron por falta de claves de API.
3. **Cobertura de subdominios**: Solo se evaluó `www.airbnb.com`. Un alcance que incluya `airbnb.com` permitiría un mapeo completo de todos los subdominios (api, mobile, support, etc.).