2026-10-30 16:56 · objetivo: airbnb.com (dominio raíz; solo consulta de registro público, el alcance real es *.airbnb.com)
máquina: portátil Windows, Sysinternals Whois v1.21
$ whois airbnb.com
-> Registrador: MarkMonitor Inc. (IANA ID 292). Creado: 2008-08-05. Actualizado: 2026-07-04. Caduca: 2028-08-05.
   Servidores DNS (8): dns1-4.p08.nsone.net (NS1) y ns-1453.awsdns-53.org, ns-1932.awsdns-49.co.uk,
   ns-474.awsdns-59.com, ns-558.awsdns-05.net (AWS Route 53).
   Estados: los seis bloqueos (client y server de Update, Transfer y Delete Prohibited). DNSSEC: unsigned.
   Titular: datos redactados por privacidad (solo se ve estado CA y país US). Contacto solo vía formulario web de MarkMonitor.
siguiente: dig +short NS/MX/TXT airbnb.com para confirmar los NS y sacar correo (SPF/DMARC) y servicios de terceros

2026-10-30 17:14 · airbnb.com (dominio raíz; solo consulta de registro público, el alcance real es *.airbnb.com)
máquina: Kali VM
$dig +short NS airbnb.com
-> 8 servidores, idénticos a los de whois: dns1-4.p08.nsone.net (NS1) y 4 de AWS Route 53 (awsdns-53.org, awsdns-49.co.uk, awsdns-59.com, awsdns-05.net).
   Sin discrepancias con el whois de 2026-10-30.
siguiente: dig +short MX y TXT airbnb.com para identificar el proveedor de correo y servicios de terceros

2026-10-30 17:24 · objetivo: airbnb.com (raíz, solo consulta DNS; alcance real *.airbnb.com)
máquina: portátil / Kali VM
$ dig SOA airbnb.com +short
-> ns-558.awsdns-05.net. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
   Primario en AWS Route 53; contacto genérico de AWS (no de Airbnb); serial 1 y temporizadores por defecto de Route 53, sin información útil sobre cambios.
siguiente: dig +short MX y TXT airbnb.com para el proveedor de correo y los servicios de terceros

2026-10-30 17:29 · objetivo: airbnb.com (raíz, solo consulta DNS; alcance real *.airbnb.com)
máquina: Kali VM
$ dig +short MX airbnb.com
-> 5 servidores de Google (aspmx.l.google.com, alt1-alt4), prioridades 1/5/5/10/10 → correo en Google Workspace
siguiente: dig TXT para ver SPF y servicios de terceros

2026-10-30 17:33 · objetivo: airbnb.com (raíz, solo consulta DNS; alcance real *.airbnb.com)
máquina: Kali VM
$ dig +short TXT airbnb.com
-> 40 registros TXT (salida completa en evidencias/dig_txt_airbnb.com.txt).
   SPF: include:spf1.airbnb.com + 4 rangos IPv4 y 6 IPv6, política -all.
   Verificaciones de servicios: Okta (SSO), Atlassian, Stripe, DocuSign, Webex, Google (x5), Microsoft, Palo Alto, Cisco, 1Password, DataDome, OpenAI, Anthropic, entre otros.
   Nota: airbnb.okta.com es de tercero (okta.com), fuera de alcance; solo contexto.
siguiente: dig +short TXT spf1.airbnb.com y dig +short TXT _dmarc.airbnb.com

2026-10-30 17:44 · objetivo: airbnb.com (raíz, solo consulta DNS; alcance real *.airbnb.com)
máquina: Kali VM
$ dig +short TXT _dmarc.airbnb.com
-> v=DMARC1; p=reject; sp=reject; pct=100; alineación relajada (aspf=r, adkim=r); fo=1; ri=3600.
   Informes a buzones de función dmarc.aggregate@ y dmarc.forensic@airbnb.com (no se contacta).
   Con el SPF -all: protección estricta contra suplantación de correo.
siguiente: dig CAA ya hecho; expandir SPF con dig +short TXT spf1.airbnb.com 

2026-10-30 17:46 · objetivo: airbnb.com (raíz, solo consulta DNS; alcance real *.airbnb.com)
máquina: Kali VM
$ dig +short CAA airbnb.com
-> issue: digicert.com, letsencrypt.org, pki.goog (Google Trust Services); iodef: caa-alerts@airbnb.com.
   Los certificados deberían venir de esas tres CA; cruzar con crt.sh.
siguiente: dig +short TXT spf1.airbnb.com y dig +short A/CNAME www.airbnb.com

2026-10-30 17:48 · objetivo: www.airbnb.com (in scope, encaja con *.airbnb.com)
máquina: Kali VM
$ dig +short A www.airbnb.com  /  dig +short CNAME www.airbnb.com
-> Cadena: www.airbnb.com → airbnb-web.production.global.product.origins.airbnb.net → san.airbnb.com.edgekey.net → e118243.a.akamaiedge.net → 7 IP (96.16.88.134-152).
   Detrás de CDN Akamai; las IP son de borde de Akamai, no de Airbnb.
   Nota: airbnb.net y akamai (edgekey/akamaiedge) son de terceros / fuera de alcance; solo contexto.
siguiente: dig +short TXT spf1.airbnb.com

2026-10-30 17:50 · objetivo: spf1.airbnb.com (in scope, encaja con *.airbnb.com)
máquina: Kali VM
$ dig +short TXT spf1.airbnb.com
-> v=spf1 include:spf2.airbnb.com + 11 rangos IPv4, política -all.
   Algunos rangos podrían ser de Google y Amazon (hipótesis, sin verificar).
siguiente: pasar a técnica 3

2026-10-30 18:32 · objetivo: airbnb.com (consulta pasiva a fuentes de terceros; alcance real *.airbnb.com)
máquina: Kali VM
$ subfinder -d airbnb.com -silent > evidencias/subfinder_raw.txt
-> 358 nombres (evidencias/subfinder_raw.txt). Modo pasivo, sin resolución activa ni fuerza bruta.
siguiente: consultar crt.sh y cruzar resultados

2026-10-30 18:37 · objetivo: airbnb.com (consulta pasiva a crt.sh; alcance real *.airbnb.com)
máquina: Kali VM
$ curl -s "https://crt.sh/?q=%25.airbnb.com&output=json" -o evidencias/crtsh_raw.json
$ jq -r '.[].name_value' evidencias/crtsh_raw.json > evidencias/crtsh_names.txt
-> JSON de 448 KB. 8494 filas (una por certificado), 480 nombres únicos sin filtrar.
siguiente: unir con subfinder aplicando filtro estricto a *.airbnb.com

2026-10-30 18:40 · objetivo: lista de subdominios (filtro estricto a *.airbnb.com, sin el dominio raíz ni correos)
máquina: Kali VM
$ f() { tr 'A-Z' 'a-z' | sed 's/^\*\.//' | grep -E '^[a-z0-9._-]+\.airbnb\.com$' | sort -u; }
$ f < evidencias/subfinder_raw.txt > /tmp/a.txt ; f < evidencias/crtsh_names.txt > /tmp/b.txt
$ sort -u /tmp/a.txt /tmp/b.txt > evidencias/subdominios_en_alcance.txt
-> 358 subdominios en alcance. subfinder: 358; crt.sh: 313.
   En las dos fuentes: 313; solo subfinder: 45; solo crt.sh: 0.
   crt.sh no aporta nombres nuevos y subfinder suele consultarlo, así que las fuentes no son independientes.
   Nota: un primer intento dio 359 líneas porque crtsh_names.txt aún no existía al unir; rehecho con el filtro estricto.
siguiente: revisar qué descartó el filtro en crt.sh

2026-10-30 18:45 · objetivo: nombres de crt.sh descartados por el filtro (fuera de *.airbnb.com)
máquina: Kali VM
$ sed 's/^\*\.//' evidencias/crtsh_names.txt | tr 'A-Z' 'a-z' | sort -u | grep -vE '^[a-z0-9._-]+\.airbnb\.com$' > evidencias/crtsh_descartados.txt
-> 167 nombres descartados; ninguno es subdominio de airbnb.com.
   Son dominios de país (airbnb.com.XX, con y sin prefijos como 8c9be, f02aa, hostcommunity, ws, www), el dominio raíz airbnb.com y createwithairbnb.com.
   Verificación: 167 = 55 (patrón airbnb.com.XX y 8c9be.airbnb.com.XX) + 112 (resto).
   Rarezas anotadas sin investigar: www.airbnb.com--com.com (origen desconocido).
   Fuera de alcance según scope.txt; son ejemplos reales de lo que el scope-guard debe bloquear.
siguiente: revisar los 45 nombres exclusivos de subfinder y separar hosts de registros

2026-10-30 19:10 · objetivo: lista de subdominios en alcance (358)
máquina: Kali VM
$ comm -23 /tmp/a.txt /tmp/b.txt
$ grep -vE '(^|\.)_' evidencias/subdominios_en_alcance.txt > evidencias/hosts_en_alcance.txt
$ grep -E '(^|\.)_' evidencias/subdominios_en_alcance.txt > evidencias/registros_servicio.txt
-> Los 45 exclusivos de subfinder son: 29 oN.email.airbnb.com (patrón de envío de correo, hipótesis por el nombre), 11 registros "_" bajo next.airbnb.com (por el nombre, parecen de Cisco, etcd, dmarc y mta-sts; hipótesis) y 5 hosts sueltos (assets, bounce.work, es.admin-lite, mta.mail, publicpolicy).
   Separación: 347 hosts + 11 registros de servicio = 358.
   Resultado técnica 3: 358 subdominios en alcance (347 hosts y 11 registros "_").
siguiente: técnica 5 (robots.txt y security.txt)

2026-10-30 20:02 · objetivo: www.airbnb.com (in scope, encaja con *.airbnb.com)
máquina: Kali VM
$ curl -sL https://www.airbnb.com/robots.txt
-> Devuelve contenido (HTTP: anotar). Guardado en evidencias/robots_airbnb.txt. N rutas Disallow distintas.
   Bloques por rastreador (Googlebot, Bingbot, Yandex, Baidu, etc.) con la misma lista; PerplexityBot y anthropic-ai añaden /rooms/ y /experiences/; cohere-ai añade además /help/, /*/things-to-do y /*/stays/; varios rastreadores de IA (GPTBot, ClaudeBot, AI2Bot, entre otros) bloqueados con Disallow: /.
   Familias de rutas: sesión y cuenta (/account, /login_with_redirect, /inbox), panel de anfitrión (/home/dashboard, /manage-listing, /my_listings), reservas y pagos (/book/, /payments/book, /reservation), API (/api/v1/trebuchet, /api/v3/LandingPageStaysQuery), fichas y usuarios (/rooms/*/reviews, /users/show) y varios (/fix-it, /fixit, /disaster/lookup).
   Sitemap: https://www.airbnb.com/sitemap-master-index.xml.gz. No se visitó ninguna ruta listada.
siguiente: security.txt

2026-10-30 20:03 · objetivo: www.airbnb.com (in scope, encaja con *.airbnb.com)
máquina: Kali VM
$ curl -sL https://www.airbnb.com/.well-known/security.txt
-> Devuelve contenido (HTTP: anotar). Guardado en evidencias/security_airbnb.txt.
   Contact y Policy: https://hackerone.com/airbnb (confirma el programa en HackerOne). Hiring: careers.airbnb.com (puestos de seguridad). Preferred-Languages: en. Canonical: https://www.airbnb.com/.well-known/security.txt. Expires: 2027-06-01. Sin campo Encryption.
   Primer intento en airbnb.com (dominio raíz) salía vacío; en www funciona.
siguiente: técnica 4 (huella tecnológica con Netcraft)

2026-10-30 20:16 · objetivo: www.airbnb.com (in scope, encaja con *.airbnb.com)
máquina: portátil (navegador)
$ Netcraft Site Report: https://sitereport.netcraft.com/?url=https://www.airbnb.com
-> Background: "Airbnb: Holiday Rentals, Cabins, Beach Houses, Unique Homes & Experiences"; rank 659; visto por primera vez en marzo de 2009; idioma inglés.
   Network: hosting y netblock de Akamai Technologies (AS20940), IPv4 2.19.176.137, DNS inverso a.2-19-176-137.deploy.static.akamaitechnologies.com, sin IPv6. Registrador MarkMonitor; organización Airbnb, Inc. (US); servidor de nombres dns1.p02.nsone.net; contacto DNS genérico de NS1.
   Tecnología (datos de hace 12 días, aprox. 2026-10-18): Envoy (proxy), Akamai (CDN); cabeceras HSTS (subdominios y preload), CSP, X-Frame-Options, X-Content-Type-Options; Google Custom Search; sin rastreadores conocidos.
   Contraste: Akamai coincide con la cadena CNAME de dig (la IP difiere, 2.19.176.137 frente a 96.16.88.x; ambas de Akamai, posible respuesta distinta según ubicación). Discrepancia: Netcraft indica DNSSEC enabled, el whois indicaba unsigned (sin resolver). Los avisos de SPF/DMARC se refieren al host www; los registros reales están en airbnb.com (ya anotados).
   Sección SSL/TLS e historial de hosting: (anotar si aparecen; si no, "no disponibles").
siguiente: técnica 6 (Shodan / InternetDB)

2026-10-30 20:23 · objetivo: hosts de evidencias/hosts_en_alcance.txt (selección de IP a partir de resolucion.txt; alcance *.airbnb.com)
máquina: Kali VM
$ grep -vE '\| $' evidencias/resolucion.txt | grep -viE 'edgekey|akamaiedge' > evidencias/resuelven_fuera_akamai.txt
$ grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' evidencias/resuelven_fuera_akamai.txt | sort -u > evidencias/ips_fuera_akamai.txt
-> De 347 hosts: 91 sin respuesta, 102 resuelven sin pasar por edgekey/akamaiedge y 154 pasan por Akamai. Las 102 líneas dan 69 IP distintas.
   Las IP de Akamai (96.16.88.x, 2.19.x.x, 23.50.54.x) se descartan: nodos compartidos de un CDN, activos de terceros.
siguiente: averiguar el propietario de las 69 IP

2026-10-30 20:26 · objetivo: 69 IP de hosts *.airbnb.com que no pasan por Akamai (consulta a registros públicos)
máquina: Kali VM
$ whois 166.117.26.42
-> Con timeout de 15 s se queda esperando; sin él, "network is unreachable". Puerto 43 bloqueado en la VM.
   Un primer bucle con whois sobre las 69 IP dio 69 líneas vacías por este motivo.
siguiente: repetir con RDAP (HTTPS)

2026-10-31 13:00 · objetivo: 69 IP de hosts *.airbnb.com que no pasan por Akamai (consulta RDAP a registros públicos)
máquina: Kali VM
$ curl -sL https://rdap.org/ip/166.117.26.42 | jq -r '.name, .country'
-> AMAZO-4 (Amazon); país null (ARIN no lo informa). RDAP funciona por HTTPS.
$ while read ip; do curl -sL https://rdap.org/ip/$ip | jq ...; done < evidencias/ips_fuera_akamai.txt > evidencias/ips_propietario.txt
-> 69 IP, ninguna en un bloque propio de Airbnb. Por nombre de bloque: SendGrid 20, Amazon 17, AT-88-Z 14 (propietario sin identificar), Twilio 9, Google 4, Zendesk 2, Akamai 2, rango compartido RFC 6598 1.
   Lectura por nombre de bloque (hipótesis): SendGrid encaja con los hosts oN.email y con el rango 50.31.32.0/19 del SPF; Zendesk con support/helpdesk.
   Observaciones: 2 IP de Akamai con otro nombre de bloque se colaron en el filtro por CNAME; 100.85.196.218 está en un rango reservado (RFC 6598).
   Todas son infraestructura de terceros, fuera de alcance como objetivo.
siguiente: muestra en Shodan InternetDB

2026-10-31 13:10 · objetivo: IP de terceros (consulta a Shodan InternetDB, sin tocar a Airbnb)
máquina: Kali VM
$ curl -s https://internetdb.shodan.io/167.89.102.165
-> {"detail":"No information available"}: Shodan no tiene datos de esa IP (bloque de SendGrid). No equivale a "sin puertos abiertos".
   Conclusión técnica 6: ninguna de las 69 IP que no pasan por Akamai está en un bloque de Airbnb; son de proveedores externos y no se consultan por ser activos de terceros. Las IP de Akamai tampoco se consultan.
   No se ha encontrado superficie expuesta de Airbnb a través de Shodan en esta fase.
siguiente: técnica 8 (correos con theHarvester y Hunter.io)

2026-10-31 13:24 · objetivo: airbnb.com (consulta a fuentes públicas de terceros; alcance real *.airbnb.com)
máquina: Kali VM
$ theHarvester -d airbnb.com -b duckduckgo,yahoo,crtsh,urlscan,otx,rapiddns -l 200 -f evidencias/harvester_airbnb
-> 0 correos, 0 IP, 0 personas. 429 "hosts" (nombres ya conocidos por subfinder, con ruido: comodines *., dominios de país, destinos CNAME pegados y una cadena mal codificada).
   Incidencias: bing no soportado en la versión 4.11.1 (se quitó); error en la fuente CRTsh (TypeError: string indices must be integers).
   Dato de contexto: varios hosts admin* apuntan a internal-tools.iap.airbnb.biz (dominio airbnb.biz, fuera de alcance; no se consulta).
   Salida guardada en evidencias/harvester_airbnb (XML y JSON). No se contactó con nadie.
siguiente: Hunter.io para el patrón de correo

2026-10-31 13:45 · objetivo: airbnb.com (consulta a Hunter.io, sin tocar a Airbnb)
máquina: Kali VM (navegador)
$ Hunter.io Domain Search: airbnb.com
-> 4.773 direcciones indexadas: 4.496 de personas y 277 genéricas; 416 clasificadas como directivos. Etiqueta "Valid" = verificación de Hunter, no mía.
   Departamentos con más direcciones (clasificación automática de Hunter): TI/Ingeniería 1.253, Operaciones y Logística 559, Dirección 341, Soporte 257, Ventas 211, Comunicación 188, Legal 180, Marketing 176, Finanzas 173, Datos e Investigación 166; 404 sin departamento.
   Patrón de correo: dominante {nombre}@airbnb.com.
   Buzones de función conocidos por el DNS: dmarc.aggregate@, dmarc.forensic@, caa-alerts@airbnb.com.
siguiente: técnica 7 (Google dorks)

2026-10-31 14:01 · objetivo: airbnb.com (consulta a Google, sin tocar a Airbnb; alcance real *.airbnb.com)
máquina: portátil s(navegador)
$ Google: site:airbnb.com filetype:pdf (y resto de dorks)
-> filetype:pdf: 10 resultados (9 en assets.airbnb.com, 1 en www.airbnb.com): guías fiscales por país, términos de servicio de 2018 y una guía de viaje. Material público de anfitriones y usuarios.
   Observaciones: un título conserva un nombre de fichero de trabajo (.docx) y la guía en español indica que fue preparada por EY para uso exclusivo de Airbnb, aunque está publicada.
   filetype:xls/xlsx/csv, filetype:doc/docx/ppt/pptx, intitle:"index of", inurl:admin, inurl:login, inurl:staging/dev/test, intext:"internal use only"/"confidential", ext:log/bak/sql: 0 resultados cada uno.
   inurl:api: 1 resultado, falso positivo (artículo de investigación de 2020 en news.airbnb.com).
   site:airbnb.com -site:www.airbnb.com: 10 subdominios visibles (hr, he, es, th, sk, samara, communitycenter, nerds, careers, news), todos ya presentes en la lista de 358.
   Contraste con DNS: admin* y staging* existen como nombres pero Google no indexa nada de ellos (hipótesis: protegidos o excluidos del rastreo).
   Hallazgos sensibles: ninguno. No se abrió ningún resultado.
siguiente: redactar mapa.md