

Ahora procedo a redactar el informe final con todos los hallazgos.

---

# Informe de Reconocimiento Pasivo: www.airbnb.com

## Alcance autorizado
- **Incluido:** `*.airbnb.com`
- **Excluido:** `blog.airbnb.com`
- **Fuera de alcance:** `example.com` (dominio distinto)

> **Nota:** `example.com`, `blog.airbnb.com` y `airbnb.com` (dominio raíz) devolvieron `BLOQUEADO` en todas las consultas, confirmando que están fuera del alcance autorizado.

---

## 1. Registro WHOIS

| Dato | Valor | Herramienta |
|------|-------|-------------|
| Estado | **No disponible** | `whois_dominio` |

La consulta WHOIS a `www.airbnb.com` falló con error de red (`connect: Network is unreachable`) y RDAP respondió 404. El dominio raíz `airbnb.com` también fue bloqueado por estar fuera del alcance `*.airbnb.com`.

---

## 2. Registros DNS

### Registro A (IPv4)
```
96.16.88.150
96.16.88.132
96.16.88.144
96.16.88.136
96.16.88.137
```
*(dns_registros)*

### Registro CNAME
```
airbnb-web.production.global.product.origins.airbnb.net.
```
*(dns_registros)*

### Registro AAAA (IPv6 / CNAMEs)
```
airbnb-web.production.global.product.origins.airbnb.net.
san.airbnb.com.edgekey.net.
e118243.a.akamaiedge.net.
```
*(dns_registros)*

> **Observación:** Las consultas para NS, MX y TXT devolvieron los mismos CNAMEs, indicando que `www.airbnb.com` es un alias que resuelve a través de Akamai CDN (edgekey.net / akamaiedge.net).

---

## 3. Subdominios

| Fuente | Resultado | Herramienta |
|--------|-----------|-------------|
| crt.sh | `www.airbnb.com` (1 subdominio en alcance, 28 filtrados) | `subdominios_crtsh` |
| Subfinder | Sin subdominios encontrados | `subdominios_subfinder` |
| DNSDumpster | No disponible (falta API key) | `subdominios_dnsdumpster` |
| Netcraft | Sin datos (posible bloqueo anti-bot) | `subdominios_netcraft` |

---

## 4. Infraestructura y Servicios (InternetDB)

| IP | Puertos | Hostname | Tags | CVEs |
|----|---------|----------|------|------|
| 96.16.88.132 | 80, 443 | a96-16-88-132.deploy.static.akamaitechnologies.com | cdn | - |
| 96.16.88.134 | 80 | a96-16-88-134.deploy.static.akamaitechnologies.com | cdn | - |
| 96.16.88.136 | 80, 443 | a96-16-88-136.deploy.static.akamaitechnologies.com | cdn | - |
| 96.16.88.137 | 80, 443 | a96-16-88-137.deploy.static.akamaitechnologies.com | cdn | - |
| 96.16.88.146 | 80, 443 | a96-16-88-146.deploy.static.akamaitechnologies.com | cdn | - |

*(internetdb)*

> **Shodan host:** No disponible (falta `SHODAN_API_KEY`).

---

## 5. URLs Históricas (Wayback Machine)

- **Total URLs en alcance:** 4.992
- **URLs de interés:** 132
- **URLs filtradas:** 8 (fuera del alcance)

**URLs destacadas de interés:**
- `https://www.airbnb.com/.well-known/amphtml/apikey.pub`
- `https://www.airbnb.com/.well-known/assetlinks.json`
- `https://www.airbnb.com/.well-known/gpc.json`
- `https://www.airbnb.com/.well-known/openid-configuration`

*(wayback_urls)*

---

## 6. Correos Electrónicos

| Fuente | Correos | Hosts |
|--------|---------|-------|
| theHarvester | 0 | 0 |
| Hunter.io | No disponible (falta `HUNTER_API_KEY`) | - |

*(correos_theharvester)*

---

## Resumen ejecutivo

1. **www.airbnb.com** está servido exclusivamente a través de **Akamai CDN**, con 5 IPs principales en el rango `96.16.88.0/24`, exponiendo puertos 80 y 443.
2. El CNAME apunta a `airbnb-web.production.global.product.origins.airbnb.net`, con una cadena de resolución que involucra `edgekey.net` y `akamaiedge.net`.
3. No se detectaron vulnerabilidades CVEs conocidas en las IPs consultadas vía InternetDB.
4. Wayback Machine reporta ~5.000 URLs archivadas, con 132 de interés (configuraciones `.well-known`, parámetros de afiliados/publicidad).
5. **example.com**, **blog.airbnb.com** y **airbnb.com** fueron excluidos por no cumplir el alcance `*.airbnb.com`.
6. Limitaciones: WHOIS inoperativo, y APIs de Shodan, DNSDumpster y Hunter no configuradas (falta keys).

---

**Herramientas utilizadas:** `whois_dominio`, `dns_registros` (A/AAAA/NS/MX/TXT/CNAME/SOA), `subdominios_crtsh`, `subdominios_subfinder`, `subdominios_dnsdumpster`, `subdominios_netcraft`, `internetdb`, `shodan_host`, `correos_theharvester`, `correos_hunter`, `wayback_urls`.