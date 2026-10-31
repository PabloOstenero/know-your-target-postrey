# Mapa de superficie de ataque · Airbnb (`*.airbnb.com`)

- **Programa:** Airbnb en HackerOne (ver `alcance.md`)
- **Alcance de este proyecto:** `*.airbnb.com` (`scope.txt`)
- **Fecha:** 2026-10-30
- **Método:** solo técnicas pasivas. No se envió tráfico de prueba a los sistemas de Airbnb, no se abrió ninguna ruta ni resultado y no se contactó con nadie.

**Cómo rastrear cada dato.** Cada afirmación lleva una referencia `[T1]` a `[T8]` a la entrada del `cuaderno.md` de esa técnica: T1 whois, T2 DNS, T3 subdominios, T4 Netcraft, T5 ficheros expuestos, T6 servicios expuestos, T7 Google dorks, T8 correos. Lo que es una lectura por el nombre, y no un hecho comprobado, se marca como *hipótesis*.

---

## 1. Resumen

Airbnb es una plataforma de alquileres vacacionales con presencia en más de 220 países y regiones [T4]. Su dominio principal, `airbnb.com`, existe desde 2008 y lo gestiona MarkMonitor, un registrador corporativo, con los seis bloqueos de transferencia, borrado y cambio activos [T1].

Lo más relevante de lo encontrado:

- **Se han identificado 358 subdominios en alcance** (347 hosts y 11 registros DNS de servicio) [T3]. La mayoría son webs por idioma, entornos no productivos y herramientas internas.
- **La web pública está detrás del CDN Akamai** [T2][T4]. De los 347 hosts, 154 resuelven a través de Akamai y 91 no devuelven IP [T3].
- **Ninguna de las 69 IP que no pasan por Akamai pertenece a un bloque de red de Airbnb.** Todas son de terceros: SendGrid, Amazon, Twilio, Google, Zendesk y otros [T6].
- **El correo está en Google Workspace** y la protección contra suplantación es estricta: SPF con `-all` y DMARC con `p=reject` [T2].
- **No se encontró nada sensible** en el `robots.txt`, en el `security.txt` ni en los Google dorks [T5][T7].

---

## 2. Dominios y subdominios

**Total:** 358 subdominios en alcance (`evidencias/subdominios_en_alcance.txt`) [T3].

| Dato | Cifra |
|---|---|
| Hosts | 347 |
| Registros DNS de servicio (empiezan por `_`) | 11 |
| Hosts con respuesta DNS | 256 |
| Hosts sin respuesta DNS | 91 |
| Hosts que resuelven a través de Akamai (CNAME `edgekey` / `akamaiedge`) | 154 |
| Hosts que resuelven sin pasar por ese CNAME | 102 (69 IP distintas) |

**Fuentes.** subfinder aportó 358 nombres y crt.sh 313. Los 313 de crt.sh estaban todos en subfinder, y subfinder suele consultar crt.sh, así que no son fuentes independientes [T3].

**Fuera de alcance, detectados y no consultados** [T3]:
- El dominio raíz `airbnb.com`, que no está en `scope.txt`.
- 167 nombres de crt.sh que no son subdominios de `airbnb.com`: dominios de país (`airbnb.com.ar`, `.au`, `.br`...) con y sin prefijo, y `createwithairbnb.com`.
- `airbnb.net`, `airbnb.biz` y los dominios de Akamai, que aparecen como destino de CNAME [T2][T8].

### Tabla representativa

No se listan los 358. Esta tabla agrupa los tipos principales, con ejemplos reales. La columna «IP» solo se rellena donde se comprobó.

| Subdominio (ejemplos) | IP | En alcance | Para qué parece servir |
|---|---|---|---|
| `www.airbnb.com` | Akamai (96.16.88.x desde `dig`; 2.19.176.137 según Netcraft) [T2][T4] | Sí | Web principal. Cadena CNAME hasta `e118243.a.akamaiedge.net`. |
| `api.airbnb.com` | Akamai (96.16.88.x) [T3] | Sí | API pública. Mismo patrón de CDN. |
| `de`, `es`, `ja`, `zh-cn`, `ar`... `.airbnb.com` | Akamai [T3] | Sí | Webs por idioma. |
| `*.next.airbnb.com` (`api.next`, `es.next`...) | no comprobada | Sí | Pila paralela con nombres «next» (*hipótesis*: nueva versión o canal de pruebas). |
| `staging`, `preprod`, `dev.staging`, `api.staging`, `api.preprod` | no comprobada | Sí | Entornos no productivos. |
| `prototype*`, `prototype-internal*` | no comprobada | Sí | Prototipos (*hipótesis*: uso interno por el nombre). |
| `admin`, `admin-lite`, `admin-next`, `admin-staging` | no comprobada | Sí | Administración. Varios apuntan a `internal-tools.iap.airbnb.biz` (dominio fuera de alcance) [T8]. |
| `akamai-ci`, `akamai-dev`, `akamai-staging` y sus `api.*` | `akamai-ci`: 166.117.26.42 y 166.117.245.89 (bloque de Amazon). `akamai-staging`: 23.50.54.x. `akamai-dev`: sin respuesta [T3][T6] | Sí | Pruebas de la integración con el CDN. Los de staging usan la red `edgekey-staging.net`. |
| `fastly`, `fastly-dev`, `api-fastly*` | sin respuesta (`api-fastly`, `api-fastly-staging`) [T3] | Sí | Pruebas con otro CDN, Fastly (*hipótesis* por el nombre). |
| `oN.email` (de `o2` a `o35`), `click.mail`, `view.mail`, `pages.mail` | no comprobada host a host | Sí | Envío de correo y marketing (*hipótesis*, coherente con los 20 IP de SendGrid) [T3][T6]. |
| `iac`, `iac-dev`, `rtpe-*`, `sip-capture-*`, `turn`, `homer`, `vidyo` | no comprobada | Sí | Infraestructura de comunicaciones: voz, vídeo y SIP (*hipótesis* por el nombre). |
| `git`, `jira`, `grafana`, `deployboard`, `helpdesk`, `tools` | no comprobada | Sí | Herramientas de ingeniería y soporte (*hipótesis* por el nombre). |
| `amex-mtls*`, `worldpay.callbacks*`, `callbacks` | no comprobada | Sí | Integraciones de pago (*hipótesis*: mTLS con Amex; retornos de Worldpay). |
| `careers`, `investors`, `news`, `newsroom`, `press`, `blog`, `community`, `support`, `developer` | `careers`, `investors`, `news`: CNAME a `byod...origins.airbnb.net` [T8] | Sí | Webs corporativas, de contenido y de comunidad. |
| `_cisco-uds`, `_collab-edge`, `_cuplogin`, `_etcd-server-ssl`, `_dmarc`, `_mta-sts` (bajo `next`) | — | Sí | Registros de servicio, no servidores. Dos parecen de Cisco y uno de etcd (*hipótesis* por el nombre) [T3]. |
| `wwww`, `ww`, `en.localhost`, `f02aa`, `d0a7e`, `8c9be`, `skywalker.us.isit` | no comprobada | Sí | Nombres inusuales, anotados como curiosidad. |

**Hosts sin respuesta (91).** Existen como nombre en alguna fuente pero no devuelven IP. No se distinguió entre un nombre inexistente y un nombre sin registro `A` [T3].

---

## 3. Infraestructura y servicios

### Registro y DNS [T1][T2]

| Aspecto | Dato |
|---|---|
| Registrador | MarkMonitor Inc. (IANA 292) |
| Fechas | Creado 2008-08-05, actualizado 2026-07-04, caduca 2028-08-05 |
| Estado | Los seis bloqueos activos (update, transfer y delete, de cliente y de servidor) |
| Servidores DNS | 8, en dos proveedores: NS1 (`dns1` a `dns4.p08.nsone.net`) y AWS Route 53 (cuatro `awsdns`). `dig` coincide con `whois` |
| SOA | Primario en Route 53, contacto genérico de AWS y valores por defecto de Route 53. No aporta información propia de Airbnb |
| Titular | Datos redactados por privacidad |
| DNSSEC | **Discrepancia sin resolver:** `whois` indica `unsigned` y Netcraft indica «enabled» [T1][T4] |
| CAA | Solo DigiCert, Let's Encrypt y Google Trust Services; avisos a un buzón de función de Airbnb |

### Hosting, CDN y tecnologías [T2][T4]

- **CDN y hosting:** Akamai Technologies (AS20940). `www.airbnb.com` pasa por la cadena `airbnb-web.production.global.product.origins.airbnb.net` → `san.airbnb.com.edgekey.net` → `e118243.a.akamaiedge.net`. Las IP `96.16.88.x` y `2.19.x.x` son de borde de Akamai, **no son servidores de Airbnb**. Las respuestas de IP difieren entre `dig` y Netcraft (*hipótesis*: Akamai responde según la ubicación).
- **Convención de nombres de origen:** los CNAME a `...origins.airbnb.net` distinguen servicio (`airbnb-web`, `airbnb-api`, `byod`), entorno (`production`, `preprod`, `next`, `development`) y región (*hipótesis* sobre su organización).
- **Tecnologías detectadas por Netcraft** (datos de hace unos 12 días, aprox. 2026-10-18): proxy Envoy y cabeceras de seguridad (HSTS con subdominios y preload, CSP, X-Frame-Options, X-Content-Type-Options). Netcraft no detectó rastreadores web.
- **Entornos de prueba del CDN:** `akamai-staging` y `akamai-dev` usan la red `edgekey-staging.net` / `akamaiedge-staging.net` (IP `23.50.54.x`). `akamai-ci` resuelve a dos IP de un bloque de Amazon [T3][T6].

### Correo [T2]

- **Proveedor:** Google Workspace (cinco registros MX de Google, prioridades 1/5/5/10/10).
- **SPF:** política `-all`, con `include:spf1.airbnb.com`, que a su vez incluye `spf2.airbnb.com`, y varios rangos IPv4 e IPv6.
- **DMARC:** `p=reject`, `sp=reject`, `pct=100`, alineación relajada, informes a buzones de función. Con el SPF, la suplantación de correo está bien cerrada.

### Servicios de terceros vistos en los TXT [T2]

Son verificaciones de dominio: indican que Airbnb *parece usar o haber usado* el servicio, sin garantía de que siga activo.

| Tipo | Servicios |
|---|---|
| Identidad y seguridad | Okta (inicio de sesión único), 1Password, Palo Alto Networks, Cisco, DataDome |
| Colaboración | Webex, Atlassian, Miro, Canva, Adobe, LucidLink, WeWork |
| Pagos y negocio | Stripe, DocuSign, Razorpay, Segment |
| Desarrollo | Gradle, páginas de estado |
| IA | OpenAI, Anthropic, ElevenLabs |
| Plataformas | Google (varias), Microsoft, Facebook, Apple, Yahoo |

`airbnb.okta.com` pertenece al dominio de Okta (tercero): es contexto, no objetivo.

### Quién es el propietario de las IP que no son de Akamai [T6]

Se obtuvo por RDAP (el puerto 43 de `whois` está bloqueado en la VM). Los nombres de bloque dan una lectura, no una prueba del servicio.

| Propietario (nombre del bloque) | IP |
|---|---|
| SendGrid | 20 |
| Amazon | 17 |
| `AT-88-Z` (sin identificar) | 14 |
| Twilio | 9 |
| Google | 4 |
| Zendesk | 2 |
| Akamai con otro nombre de bloque | 2 |
| Rango compartido RFC 6598 (`100.85.196.218`) | 1 |
| **Total** | **69** |

Ninguna está en un bloque propio de Airbnb. La IP del rango reservado es una rareza de configuración DNS anotada sin más.

### Shodan [T6]

- Las IP de Akamai no se consultaron: son nodos compartidos de un CDN.
- Las IP de terceros no se consultaron por ser activos fuera de alcance.
- La consulta de muestra a InternetDB (`167.89.102.165`, bloque de SendGrid) devolvió «No information available», que no equivale a «sin puertos abiertos».
- **Resultado:** no se encontró superficie expuesta de Airbnb a través de Shodan.

### Ficheros expuestos y buscadores [T5][T7]

- **`robots.txt` de `www.airbnb.com`:** bloques por rastreador con la misma lista de rutas, y bloqueo total para varios rastreadores de IA. Familias de rutas excluidas: sesión y cuenta, panel de anfitrión, reservas y pagos, API versionadas (`/api/v1/trebuchet`, `/api/v3/LandingPageStaysQuery`), fichas y usuarios, y varias rutas de diagnóstico (`/fix-it`, `/fixit`, `/disaster/lookup`). Sitemap: `https://www.airbnb.com/sitemap-master-index.xml.gz`. Ninguna ruta se visitó.
- **`security.txt`:** existe; `Contact` y `Policy` apuntan a `hackerone.com/airbnb`, lo que confirma el programa desde el propio dominio. Caduca el 2027-06-01. No incluye clave de cifrado.
- **Google dorks:** 10 PDF públicos (guías fiscales por país, términos de servicio de 2018 y una guía de viaje), todos de aspecto público. Cero resultados en hojas de cálculo, documentos Word y presentaciones, `index of`, `inurl:admin`, `inurl:login`, `inurl:staging/dev/test`, textos de uso interno y ficheros `.log/.bak/.sql`. Sin hallazgos sensibles. Los hosts `admin*` y `staging*` existen en el DNS, pero Google no indexa nada de ellos (*hipótesis*: protegidos o excluidos del rastreo).

---

## 4. Correos y personas

- **theHarvester:** 0 correos, 0 IP y 0 personas. Una fuente (CRTsh) dio error de la herramienta y bing no está soportado en la versión usada [T8].
- **Hunter.io:** 4.773 direcciones indexadas para `airbnb.com`: 4.496 de personas y 277 genéricas, con 416 clasificadas como directivos [T8]. Las etiquetas de verificación son de Hunter, no mías.
- **Patrón de correo:** el dominante parece `{nombre}.{apellido}@airbnb.com` (*hipótesis* a partir de las direcciones visibles; alguna cuenta antigua usa solo el nombre) [T8].
- **Departamentos con más direcciones** (clasificación automática de Hunter, orden de magnitud): TI e ingeniería (~1.250), operaciones y logística (~560), dirección (~340), soporte (~260), ventas (~210), comunicación (~190), legal (~180), marketing (~175), finanzas (~175), datos e investigación (~165). Unas 400 sin departamento [T8].
- **Buzones de función** (vistos en el DNS, no son personas) [T2]: direcciones de informes DMARC agregados y forenses, y de avisos CAA, todos con el patrón `función@airbnb.com`.
- **Personas:** no se copiaron nombres ni direcciones al cuaderno ni a este mapa, no se usó la función de revelar ni la de exportar de Hunter, y no se contactó con nadie.

---

## 5. Puntos de interés para la fase activa

Se proponen tres elementos. Antes de cualquier prueba, hay que releer `alcance.md` (reglas del programa, cabecera de identificación `X-HackerOne-Researcher` y rechazo de resultados de escáner sin validar).

### 1. Entornos no productivos y herramientas de administración

*Qué:* `staging`, `preprod`, `dev.staging`, `prototype*`, `admin`, `admin-lite`, `admin-next`, `admin-staging` y los entornos `akamai-ci` / `akamai-dev`.

*Por qué:* son muchos nombres con aspecto de no producción y de uso interno. Varios apuntan a `internal-tools.iap.airbnb.biz` [T8], lo que sugiere herramientas internas tras un proxy de identidad (*hipótesis* por el nombre). Además, Google no indexa nada de ellos [T7], así que lo que se vea ahí no estará en los buscadores. Los entornos no productivos suelen tener una configuración menos cuidada que producción. Hay que comprobar antes que cada host está en `*.airbnb.com` y que su destino no sea de un tercero.

### 2. Las API y sus variantes por entorno

*Qué:* `api.airbnb.com`, `api.next`, `api.preprod`, `api.staging`, `api.dev.staging`, `api.akamai-*` y las rutas de API que aparecen en el `robots.txt` (`/api/v1/trebuchet`, `/api/v3/LandingPageStaysQuery`, `/api/v2/google_place_photos`) [T3][T5].

*Por qué:* hay una API de producción y réplicas por entorno, con una convención de nombres de origen clara (`airbnb-api.production...`, `airbnb-api.preprod...`, `airbnb-api.next...`) [T8]. El `robots.txt` revela versiones distintas de la API. Comparar el comportamiento entre entornos es una forma habitual de encontrar diferencias de configuración. Hay que respetar las reglas del programa sobre ritmo de peticiones y no probar nada que parezca denegación de servicio.

### 3. Integraciones de pago y retornos de terceros

*Qué:* `amex-mtls`, `amex-mtls-staging`, `worldpay.callbacks`, `worldpay.callbacks.staging` y `callbacks` [T3].

*Por qué:* son los nombres que más claramente apuntan a flujos con terceros financieros (*hipótesis* por el nombre), con autenticación mutua en el caso de Amex y direcciones de retorno en el de Worldpay. Es el punto donde un fallo tendría más impacto potencial. También es el más delicado: los sistemas del tercero quedan fuera de alcance y el programa prohíbe afectar a datos y servicio reales, así que haría falta moverse con especial cuidado y quedarse en lo que sea de Airbnb.

---

## 6. Limitaciones y pendientes

- **Fuentes no independientes.** subfinder y crt.sh se solapan, así que la cifra de 358 depende sobre todo de una fuente [T3].
- **Datos con fecha.** Netcraft refleja un rastreo de hace unos 12 días, y Shodan y Hunter son fotos de sus propias bases de datos [T4][T6][T8].
- **Hipótesis por el nombre.** Las funciones de muchos hosts (comunicaciones, herramientas de ingeniería, pagos, correo de marketing) se deducen del nombre y no se verificaron.
- **Discrepancia sin resolver:** DNSSEC (`whois` frente a Netcraft) [T1][T4].
- **Sin resolver, por tiempo:** el propietario del bloque `AT-88-Z` (14 IP); el motivo exacto de los 91 hosts sin respuesta; la IP de cada host de entornos y administración; y las técnicas opcionales (Wayback Machine, exiftool, LinkedIn, Have I Been Pwned, Sherlock).
- **Alcance:** la política de Airbnb habla de «sitios localizados», pero este proyecto se limita a `*.airbnb.com`. Los dominios de país `airbnb.com.XX` se dejaron fuera [T3].
- **Verificación pendiente de `policy_scopes`** (ver `alcance.md`).