"""Herramientas iniciales de reconocimiento. AQUÍ PUEDES AÑADIR LAS TUYAS.

WHOIS (whois.py), DNS y crt.sh ya están implementadas y activas en lanzar.py.
DNS y crt.sh proceden de la solución del profesor (herramientas/recon.py).

Para ampliar: una tarea por función, @protegida, sin shell, con timeout,
salida recortada, errores como texto y resultados filtrados por el alcance.
Importa tu nueva función en lanzar.py y añádela a HERRAMIENTAS.

Ideas: subdominios_subfinder, wayback_urls, correos (theHarvester / hunter.io),
infraestructura_ip, correo_postura (SPF/DMARC/MTA-STS/CAA), urlscan, shodan_host.
"""

import os
import shutil
import socket
import tempfile
import re
import json
import subprocess
import urllib.parse
import urllib.request

from guard import protegida, filtrar
from whois import recortar

UA = "aap-recon/1.0 (educativo; IES Rafael Alberti)"
TIPOS_DNS = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}


def _http(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


@protegida(objetivo="dominio")
def dns_registros(dominio: str, tipo: str = "A") -> str:
    """Consulta registros DNS de un dominio. tipo: A, AAAA, MX, NS, TXT, CNAME o SOA.
    Devuelve los valores, uno por línea."""
    tipo = tipo.upper()
    if tipo not in TIPOS_DNS:
        return f"ERROR: tipo DNS no válido ({tipo}). Usa uno de: {', '.join(sorted(TIPOS_DNS))}."
    try:
        r = subprocess.run(["dig", "+short", tipo, dominio],
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return "ERROR: dig no respondió en 20 segundos."
    except OSError as e:
        return recortar(f"ERROR: no se pudo ejecutar dig: {e}")
    if r.returncode != 0:
        return recortar(f"ERROR: dig falló ({r.returncode}): {r.stderr.strip() or 'sin detalles'}")
    salida = recortar(r.stdout.strip())
    return salida or f"Sin registros {tipo} para {dominio}."


@protegida(objetivo="dominio")
def subdominios_crtsh(dominio: str) -> str:
    """Enumera subdominios de un dominio por transparencia de certificados (crt.sh).
    Pasivo: no toca el objetivo. Devuelve solo los subdominios dentro del alcance."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(dominio)}&output=json"
    try:
        datos = json.loads(_http(url, timeout=90))
    except Exception as e:
        return (f"ERROR: crt.sh no respondió ({e}). crt.sh suele ir lento; "
                "puedes reintentar más tarde o añadir otra fuente de subdominios.")
    if not isinstance(datos, list) or any(
        not isinstance(fila, dict) or not isinstance(fila.get("name_value"), str)
        for fila in datos
    ):
        return "ERROR: crt.sh devolvió un formato de certificados inesperado."
    nombres = set()
    for fila in datos:
        for n in str(fila.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n:
                nombres.add(n)
    dentro, fuera = filtrar(sorted(nombres))
    cab = f"{len(dentro)} subdominios en alcance ({fuera} filtrados por estar fuera):\n"
    return recortar(cab + "\n".join(dentro))

def _dig(tipo: str, nombre: str) -> str:
    """dig +short sin shell y con timeout. Devuelve texto (errores incluidos)."""
    try:
        r = subprocess.run(["dig", "+short", tipo, nombre],
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return f"ERROR: dig {tipo} {nombre} no respondió en 20 s."
    except OSError as e:
        return f"ERROR: no se pudo ejecutar dig: {e}"
    if r.returncode != 0:
        return f"ERROR: dig falló ({r.returncode}): {r.stderr.strip() or 'sin detalles'}"
    return r.stdout.strip()


@protegida(objetivo="dominio")
def correo_postura(dominio: str) -> str:
    """Evalúa la postura de seguridad del correo de un dominio: MX, SPF, DMARC,
    MTA-STS y CAA. Pasivo (solo consultas DNS). Indica si SPF/DMARC son débiles."""
    mx = _dig("MX", dominio)
    txt = _dig("TXT", dominio)
    dmarc_txt = _dig("TXT", f"_dmarc.{dominio}")
    mtasts_txt = _dig("TXT", f"_mta-sts.{dominio}")
    caa = _dig("CAA", dominio)

    spf = [l for l in txt.splitlines() if "v=spf1" in l.lower()]
    dmarc = [l for l in dmarc_txt.splitlines() if "v=dmarc1" in l.lower()]
    mtasts = [l for l in mtasts_txt.splitlines() if "v=stsv1" in l.lower()]

    out = [f"MX:\n{mx or '(ninguno)'}"]

    # SPF
    if not spf:
        out.append("SPF: AUSENTE")
    else:
        s = spf[0].lower()
        if "-all" in s:
            nivel = "estricto (-all)"
        elif "~all" in s:
            nivel = "blando (~all)"
        else:
            nivel = "DÉBIL (?all/+all o sin 'all')"
        out.append(f"SPF: {spf[0]}\n  -> {nivel}")

    # DMARC
    if not dmarc:
        out.append("DMARC: AUSENTE")
    else:
        d = dmarc[0].lower().replace(" ", "")
        pol = "reject" if "p=reject" in d else "quarantine" if "p=quarantine" in d else "none (solo monitoriza)"
        out.append(f"DMARC: {dmarc[0]}\n  -> política: {pol}")

    out.append(f"MTA-STS: {mtasts[0] if mtasts else 'AUSENTE'}")
    out.append(f"CAA: {caa or 'AUSENTE (cualquier CA puede emitir)'}")

    return recortar("\n".join(out))
    
def _bin_subfinder():
    """Ruta del ejecutable de subfinder (PATH o ~/go/bin), o None."""
    ruta = shutil.which("subfinder")
    if ruta:
        return ruta
    alt = os.path.expanduser("~/go/bin/subfinder")
    return alt if os.access(alt, os.X_OK) else None


@protegida(objetivo="dominio")
def subdominios_subfinder(dominio: str) -> str:
    """Enumera subdominios de un dominio con subfinder (fuentes pasivas: certificados,
    DNS pasivo, archivos web, etc.). Pasivo: no toca el objetivo. Devuelve solo los
    subdominios dentro del alcance."""
    if dominio.startswith("-"):
        return "ERROR: dominio no válido."
    binario = _bin_subfinder()
    if not binario:
        return ("ERROR: subfinder no encontrado (ni en PATH ni en ~/go/bin). "
                "Instálalo con 'sudo apt install subfinder' o 'go install'.")
    try:
        r = subprocess.run([binario, "-d", dominio, "-silent", "-nc", "-max-time", "3"],
                           capture_output=True, text=True, timeout=240)
    except subprocess.TimeoutExpired:
        return "ERROR: subfinder no terminó en 240 s. Reintenta o usa subdominios_crtsh."
    except OSError as e:
        return recortar(f"ERROR: no se pudo ejecutar subfinder: {e}")
    if r.returncode != 0:
        return recortar(f"ERROR: subfinder falló ({r.returncode}): "
                        f"{r.stderr.strip() or 'sin detalles'}")

    nombres = {l.strip().lstrip("*.").lower() for l in r.stdout.splitlines() if l.strip()}
    if not nombres:
        return f"subfinder no encontró subdominios para {dominio}."
    dentro, fuera = filtrar(sorted(nombres))
    cab = f"{len(dentro)} subdominios en alcance ({fuera} filtrados por estar fuera):\n"
    return recortar(cab + "\n".join(dentro))

# ---------- utilidades comunes ----------

def _http_h(url: str, headers: dict | None = None, timeout: int = 30) -> str:
    h = {"User-Agent": UA, **(headers or {})}
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _limpia(e: Exception, *secretos: str) -> str:
    """Texto del error sin claves."""
    t = str(e)
    for s in secretos:
        if s:
            t = t.replace(s, "***")
    return t


def _ips(dominio: str, maximo: int = 5) -> list[str]:
    try:
        info = socket.getaddrinfo(dominio, None, socket.AF_INET)
    except OSError:
        return []
    return sorted({i[4][0] for i in info})[:maximo]


def _bin(nombre: str):
    ruta = shutil.which(nombre)
    if ruta:
        return ruta
    alt = os.path.expanduser(f"~/go/bin/{nombre}")
    return alt if os.access(alt, os.X_OK) else None


# ---------- DNSDumpster ----------

@protegida(objetivo="dominio")
def subdominios_dnsdumpster(dominio: str) -> str:
    """Enumera hosts, IPs, NS y MX de un dominio con la API de DNSDumpster.
    Pasivo. Devuelve solo los hosts dentro del alcance."""
    clave = os.environ.get("DNSDUMPSTER_API_KEY")
    if not clave:
        return "ERROR: falta DNSDUMPSTER_API_KEY en el entorno/.env."
    try:
        datos = json.loads(_http_h(
            f"https://api.dnsdumpster.com/domain/{urllib.parse.quote(dominio)}",
            {"X-API-Key": clave}, timeout=60))
    except Exception as e:
        return recortar(f"ERROR: DNSDumpster falló ({_limpia(e, clave)}). Límite: 1 petición cada 2 s.")
    if not isinstance(datos, dict):
        return "ERROR: DNSDumpster devolvió un formato inesperado."

    hosts = {}
    for seccion in ("a", "ns", "mx", "cname"):
        filas = datos.get(seccion)
        if not isinstance(filas, list):
            continue
        for f in filas:
            if isinstance(f, dict) and isinstance(f.get("host"), str):
                ips = [i.get("ip") for i in f.get("ips", []) if isinstance(i, dict) and i.get("ip")]
                hosts[f["host"].strip().lower().rstrip(".")] = ips
    if not hosts:
        return f"DNSDumpster no devolvió hosts para {dominio}."
    dentro, fuera = filtrar(sorted(hosts))
    lineas = [f"{h}  {', '.join(hosts[h])}".rstrip() for h in dentro]
    cab = f"{len(dentro)} hosts en alcance ({fuera} filtrados por estar fuera):\n"
    return recortar(cab + "\n".join(lineas))


# ---------- Netcraft (best effort) ----------

@protegida(objetivo="dominio")
def subdominios_netcraft(dominio: str) -> str:
    """Busca subdominios en Netcraft Site Report/Search DNS. No hay API pública:
    se lee el HTML, así que puede fallar por bloqueo anti-bot. Pasivo."""
    url = ("https://searchdns.netcraft.com/?restriction=site+contains&position=limited"
           f"&host={urllib.parse.quote(dominio)}")
    try:
        html = _http_h(url, timeout=45)
    except Exception as e:
        return recortar(f"ERROR: Netcraft no respondió ({e}).")
    patron = re.compile(r"[a-z0-9][a-z0-9._-]*\." + re.escape(dominio.lower()), re.I)
    nombres = {m.group(0).lower() for m in patron.finditer(html)}
    if not nombres:
        return ("Netcraft no devolvió subdominios (posible bloqueo anti-bot o sin datos). "
                "Resultado no concluyente.")
    dentro, fuera = filtrar(sorted(nombres))
    return recortar(f"{len(dentro)} subdominios en alcance ({fuera} filtrados por estar fuera):\n"
                    + "\n".join(dentro))


# ---------- InternetDB (sin clave) ----------

@protegida(objetivo="dominio")
def internetdb(dominio: str) -> str:
    """Resuelve las IPs del dominio y consulta InternetDB de Shodan (gratis, sin clave):
    puertos abiertos, CPEs, hostnames, tags y CVEs conocidos. Pasivo: no escanea."""
    ips = _ips(dominio)
    if not ips:
        return f"No se pudo resolver {dominio} a IPv4."
    out = []
    for ip in ips:
        try:
            d = json.loads(_http_h(f"https://internetdb.shodan.io/{ip}", timeout=20))
            out.append(f"{ip}\n  puertos: {d.get('ports')}\n  hostnames: {d.get('hostnames')}\n"
                       f"  cpes: {d.get('cpes')}\n  tags: {d.get('tags')}\n  vulns: {d.get('vulns')}")
        except urllib.error.HTTPError as e:
            out.append(f"{ip}\n  " + ("sin datos en InternetDB" if e.code == 404 else f"ERROR HTTP {e.code}"))
        except Exception as e:
            out.append(f"{ip}\n  ERROR: {e}")
    return recortar("\n".join(out))


# ---------- Shodan (con clave) ----------

@protegida(objetivo="dominio")
def shodan_host(dominio: str) -> str:
    """Resuelve las IPs del dominio y consulta la API de Shodan: organización, ASN,
    puertos, servicios/banners resumidos y CVEs. Pasivo (datos ya indexados)."""
    clave = os.environ.get("SHODAN_API_KEY")
    if not clave:
        return "ERROR: falta SHODAN_API_KEY en el entorno/.env."
    ips = _ips(dominio)
    if not ips:
        return f"No se pudo resolver {dominio} a IPv4."
    out = []
    for ip in ips:
        try:
            d = json.loads(_http_h(f"https://api.shodan.io/shodan/host/{ip}?key={clave}", timeout=30))
        except urllib.error.HTTPError as e:
            msg = {401: "clave inválida", 403: "plan sin acceso", 404: "sin datos", 429: "límite de tasa"}.get(e.code, f"HTTP {e.code}")
            out.append(f"{ip}: {msg}")
            continue
        except Exception as e:
            out.append(f"{ip}: ERROR {_limpia(e, clave)}")
            continue
        servicios = [f"{s.get('port')}/{s.get('transport')} {s.get('product', '')} {s.get('version', '')}".strip()
                     for s in d.get("data", []) if isinstance(s, dict)]
        out.append(f"{ip}  org={d.get('org')}  asn={d.get('asn')}  pais={d.get('country_name')}\n"
                   f"  puertos: {d.get('ports')}\n  servicios: {servicios[:15]}\n"
                   f"  vulns: {list(d.get('vulns', []))[:15]}")
    return recortar("\n".join(out))


# ---------- theHarvester ----------

# Solo fuentes pasivas y sin clave. Comprueba las de tu versión con: theHarvester -h
FUENTES_HARVESTER = "crtsh,hackertarget,rapiddns,otx,urlscan,duckduckgo"


@protegida(objetivo="dominio")
def correos_theharvester(dominio: str) -> str:
    """Recopila correos, hosts e IPs de un dominio con theHarvester (fuentes públicas
    pasivas). Devuelve solo hosts y correos dentro del alcance. Puede tardar minutos."""
    if dominio.startswith("-"):
        return "ERROR: dominio no válido."
    binario = _bin("theHarvester") or _bin("theharvester")
    if not binario:
        return "ERROR: theHarvester no encontrado (sudo apt install theharvester / pipx install theHarvester)."
    with tempfile.TemporaryDirectory(prefix="harvester_") as tmp:
        base = os.path.join(tmp, "res")
        try:
            r = subprocess.run([binario, "-d", dominio, "-b", FUENTES_HARVESTER, "-l", "200", "-f", base],
                               capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return "ERROR: theHarvester no terminó en 300 s."
        except OSError as e:
            return recortar(f"ERROR: no se pudo ejecutar theHarvester: {e}")
        try:
            with open(base + ".json", encoding="utf-8") as f:
                datos = json.load(f)
        except (OSError, ValueError):
            return recortar(f"ERROR: theHarvester no generó JSON ({r.returncode}): "
                            f"{(r.stderr or r.stdout).strip()[-500:] or 'sin detalles'}")
    if not isinstance(datos, dict):
        return "ERROR: formato de theHarvester inesperado."

    hosts = {str(h).split(":")[0].strip().lower() for h in datos.get("hosts", []) if h}
    correos = {str(c).strip().lower() for c in datos.get("emails", []) if "@" in str(c)}
    correos = {c for c in correos if c.endswith("@" + dominio.lower()) or c.endswith("." + dominio.lower())}
    h_dentro, h_fuera = filtrar(sorted(hosts))
    return recortar(f"CORREOS ({len(correos)}):\n" + "\n".join(sorted(correos))
                    + f"\n\nHOSTS en alcance ({len(h_dentro)}, {h_fuera} filtrados):\n" + "\n".join(h_dentro))


# ---------- hunter.io ----------

@protegida(objetivo="dominio")
def correos_hunter(dominio: str) -> str:
    """Busca correos corporativos de un dominio en hunter.io (patrón de correo, cargos,
    nivel de confianza). Pasivo. Contiene datos personales: usar solo lo necesario."""
    clave = os.environ.get("HUNTER_API_KEY")
    if not clave:
        return "ERROR: falta HUNTER_API_KEY en el entorno/.env."
    url = f"https://api.hunter.io/v2/domain-search?domain={urllib.parse.quote(dominio)}&limit=10"
    try:
        d = json.loads(_http_h(url, {"X-API-KEY": clave}, timeout=30))
    except urllib.error.HTTPError as e:
        return f"ERROR: hunter.io HTTP {e.code} ({ {401: 'clave inválida', 429: 'límite de uso'}.get(e.code, 'revisa la clave/plan') })."
    except Exception as e:
        return recortar(f"ERROR: hunter.io falló ({_limpia(e, clave)}).")
    data = d.get("data") if isinstance(d, dict) else None
    if not isinstance(data, dict):
        return "ERROR: hunter.io devolvió un formato inesperado."
    lineas = [f"Organización: {data.get('organization')}  Patrón: {data.get('pattern')}"]
    for c in data.get("emails", []):
        if isinstance(c, dict) and c.get("value"):
            lineas.append(f"{c['value']}  {c.get('position') or ''}  conf={c.get('confidence')}")
    if len(lineas) == 1:
        lineas.append("Sin correos públicos.")
    return recortar("\n".join(lineas))
    
EXT_RUIDO = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|css|woff2?|ttf|eot|mp[34]|avi|map)(\?|$)", re.I)
INTERESANTE = re.compile(
    r"(\.(env|bak|old|sql|zip|tar|gz|log|conf|config|ini|git|swp|xml|json|yml|yaml)(\?|$)"
    r"|admin|login|backup|dump|config|api|upload|debug|test|staging|phpinfo|\.git/)", re.I)


@protegida(objetivo="dominio")
def wayback_urls(dominio: str) -> str:
    """Lista URLs históricas de un dominio y sus subdominios desde Wayback Machine
    (archive.org). Pasivo: no toca el objetivo. Descarta imágenes/CSS/fuentes, solo
    devuelve URLs dentro del alcance y pone primero las de interés (admin, login,
    backups, configuración, API, .env, .git...)."""
    if dominio.startswith("-"):
        return "ERROR: dominio no válido."
    url = ("https://web.archive.org/cdx/search/cdx?"
           f"url={urllib.parse.quote(dominio)}&matchType=domain&output=json"
           "&fl=original&collapse=urlkey&filter=statuscode:200&limit=5000")
    try:
        datos = json.loads(_http(url, timeout=90))
    except Exception as e:
        return (f"ERROR: Wayback Machine no respondió ({e}). Suele ir lenta; "
                "reintenta más tarde.")
    if not isinstance(datos, list):
        return "ERROR: Wayback devolvió un formato inesperado."
    if len(datos) <= 1:                      # la fila 0 es la cabecera
        return f"Wayback no tiene URLs archivadas para {dominio}."

    urls = set()
    for fila in datos[1:]:
        if isinstance(fila, list) and fila and isinstance(fila[0], str):
            u = fila[0].strip()
            if u and not EXT_RUIDO.search(u):
                urls.add(u)

    # Filtrado por alcance sobre el host de cada URL
    def host(u):
        try:
            return (urllib.parse.urlsplit(u).hostname or "").lower()
        except ValueError:
            return ""

    hosts = {h for h in (host(u) for u in urls) if h}
    permitidos, _ = filtrar(sorted(hosts))
    permitidos = set(permitidos)
    dentro = sorted(u for u in urls if host(u) in permitidos)
    fuera = len(urls) - len(dentro)

    if not dentro:
        return f"Sin URLs en alcance para {dominio} ({fuera} filtradas por estar fuera)."

    interesantes = [u for u in dentro if INTERESANTE.search(u)]
    resto = [u for u in dentro if u not in set(interesantes)]
    cab = (f"{len(dentro)} URLs en alcance ({fuera} filtradas por estar fuera), "
           f"{len(interesantes)} de interés:\n")
    cuerpo = ("== DE INTERÉS ==\n" + "\n".join(interesantes) + "\n\n" if interesantes else "")
    cuerpo += "== RESTO ==\n" + "\n".join(resto)
    return recortar(cab + cuerpo)
    
