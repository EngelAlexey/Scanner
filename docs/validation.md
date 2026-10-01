# Validación

Cada fila compara el resultado del revisor con el de una herramienta de referencia. Una diferencia se anota con su causa.

## Fase 1: cabeceras de seguridad (2026-09-30)

El revisor se ejecutó con `pnpm scan <dominio>` en Node 24.19.0. La referencia es la API v2 de Mozilla Observatory (`algorithm_version` 6), porque securityheaders.com responde 403 a las peticiones automáticas.

| Sitio | Comprobación | Revisor | Observatory |
|---|---|---|---|
| alexherrera.dev | CSP | `csp-missing` | `csp-not-implemented` |
| alexherrera.dev | Marcos | Aprueba | `x-frame-options-sameorigin-or-deny` |
| alexherrera.dev | `nosniff` | Aprueba | `x-content-type-options-nosniff` |
| alexherrera.dev | Referrer-Policy | Aprueba | `referrer-policy-private` |
| alexherrera.dev | HSTS | Aprueba | `hsts-preloaded` |
| github.com | CSP | Aprueba | `csp-implemented-with-unsafe-inline-in-style-src-only` |
| github.com | Marcos | Aprueba | `x-frame-options-implemented-via-csp` |
| github.com | `nosniff` | Aprueba | `x-content-type-options-nosniff` |
| github.com | Referrer-Policy | Aprueba | `referrer-policy-private` |
| github.com | HSTS | Aprueba | `hsts-preloaded` |
| wikipedia.org | CSP | `csp-missing` | `csp-not-implemented` |
| wikipedia.org | Marcos | `framing-allowed` | `x-frame-options-not-implemented` |
| wikipedia.org | `nosniff` | `nosniff-missing` | `x-content-type-options-not-implemented` |
| wikipedia.org | Referrer-Policy | `referrer-policy-missing` | `referrer-policy-not-implemented` |
| wikipedia.org | HSTS | Aprueba | `hsts-preloaded` |

Coinciden las 15 filas. Observatory dio B (70 puntos) a alexherrera.dev, A+ (115) a github.com y C (50) a wikipedia.org.

Diferencias esperadas:

- **Permissions-Policy.** Observatory no la revisa. El revisor la marca en los tres sitios, porque ninguno restringe `camera`, `microphone` y `geolocation`.
- **Versión del servidor.** Observatory no la revisa. El revisor marca `Server: ATS/9.2.15` en wikipedia.org.
- **SRI.** Observatory falla alexherrera.dev y github.com por cargar scripts externos sin `integrity`. El revisor excluye los cargadores que cambian por diseño, como Google Tag Manager, así que esa comprobación no coincidirá en esos casos.

## Fase 2: blindaje (2026-09-30)

### Pruebas de viabilidad

| Prueba | Resultado |
|---|---|
| TypeScript sin compilar en Vercel | El compilador de Vercel genera un `.js` por archivo y conserva la extensión `.ts` en cada `import`. La función falla con `ERR_MODULE_NOT_FOUND` y responde 500. `rewriteRelativeImportExtensions` en `tsconfig.json` lo corrige. La API de producción estuvo caída unos 5 minutos el 2026-09-30 por este motivo |
| Turnstile con la clave de prueba | `siteverify` devuelve `hostname: example.com`, sin `action`, y `metadata.result_with_testing_key: true`. Por eso `vercel dev` no exige `action`, y un despliegue rechaza las claves de prueba |
| IP del visitante en `vercel dev` | `x-real-ip` llega como `::1` aunque la petición traiga otro valor. Falta la prueba en producción con el límite activo |
| Procesos de `vercel dev` | Cada petición se ejecuta en un proceso nuevo. Un secreto aleatorio en memoria cambiaba en cada análisis, y el límite por IP no se aplicaba. `vercel dev` usa ahora un secreto local fijo |

### Tabla 6.2 del plan técnico

| Prueba | Dónde | Resultado |
|---|---|---|
| Nombres locales, IP literales y formatos raros | `test/target.test.ts` | Rechazados sin conexión |
| Bordes de rangos privados y metadatos de nubes | `test/address-policy.test.ts` | Solo pasan las direcciones públicas |
| Dominio público que apunta a una IP privada | `test/resolver.test.ts` | `blocked_address` |
| Cambio de DNS a mitad del análisis | `test/safe-request.test.ts` | Una sola resolución por host |
| Redirección a una IP privada, a una IP literal o a otro puerto | `test/safe-request.test.ts` | Se detiene en ese salto, sin conectar al destino |
| 20 redirecciones | `test/safe-request.test.ts` | Exactamente 6 peticiones |
| Respuesta lenta: cabeceras que no llegan y cuerpo a 1 byte cada 100 ms | `test/safe-request.test.ts` | Corta al límite con `timeout` |
| Página de 5 MB, bomba gzip, bomba brotli, cuerpo sin fin y `Content-Length` falso | `test/safe-request.test.ts` | Se conservan exactamente 2 MB |
| Seis análisis desde la misma IP, también en un mismo /64 de IPv6 | `test/scan-request.test.ts`; a mano con `vercel dev` | El sexto recibe 429 con `Retry-After` |
| Llamada sin token, con token falso o repetido | `test/scan-request.test.ts`, `test/turnstile.test.ts` | 403, sin escritura en la base de datos |
| Token de otro host, de otra acción o de más de 300 s | `test/turnstile.test.ts` | 403 |
| Cloudflare no responde | `test/turnstile.test.ts`, `test/scan-request.test.ts` | 503, falla cerrado |
| IP que ve la API | Pendiente | Prueba en producción: un token válido enviado con `curl` y un `x-real-ip` falso, después de agotar el límite de la IP real |

### Pendiente

La detección de `http2-only` no está hecha: un servidor que solo habla HTTP/2 da hoy `connection_failed`. Los límites de Vercel Hobby y las horas de cómputo de Neon se anotan al activar el análisis en producción.

## Fase 3: revisiones completas (2026-10-01)

El revisor se ejecutó con `pnpm scan <dominio>` en Node 24.19.0, desde Costa Rica. Un análisis tardó entre 3 y 5 segundos en sitios grandes y hasta 15 en badssl.com.

### Certificados y TLS con badssl.com

| Sitio | Caso | Revisor |
|---|---|---|
| expired.badssl.com | Certificado vencido | `cert-expired` |
| wrong.host.badssl.com | Certificado de otro dominio | `cert-name-mismatch` |
| self-signed.badssl.com | Certificado autofirmado | `cert-untrusted` |
| untrusted-root.badssl.com | Raíz que no es de confianza | `cert-untrusted` |
| incomplete-chain.badssl.com | Falta el certificado intermedio | `cert-chain-incomplete` |
| sha256.badssl.com | Certificado válido | Sin hallazgos de certificado |
| mixed-script.badssl.com | Script cargado por HTTP | `mixed-content` |
| hsts.badssl.com | HSTS de 6 meses | `hsts-short` |

Coinciden las 8 filas. Todos los servidores de badssl.com aceptan TLS 1.0 y 1.1 y no negocian TLS 1.3, así que todos dan además `tls-legacy` y `tls13-missing`.

badssl.com corta conexiones cuando una misma IP abre varias a la vez. En la primera versión, el revisor abría hasta cinco y daba `https-unavailable` en sitios que sí respondían. Ahora la sonda TLS espera a la respuesta HTTPS, prueba TLS 1.0 y 1.1 una tras otra y reintenta una vez tras un corte. Si la sonda falla pero la página llegó por HTTPS, la conexión cuenta como disponible y el certificado queda sin revisar.

### Comparación con Mozilla Observatory

| Sitio | Comprobación | Revisor | Observatory |
|---|---|---|---|
| github.com | Redirección a HTTPS | Aprueba | `redirection-all-redirects-preloaded` |
| github.com | Cookies | `cookie-no-httponly` (informativa) | `cookies-secure-with-httponly-sessions-and-samesite` |
| github.com | SRI | Aprueba | `sri-not-implemented-but-external-scripts-loaded-securely` |
| www.google.com | Redirección a HTTPS | `http-no-redirect` | `redirection-to-https` |
| www.google.com | HSTS | `hsts-missing` | `hsts-implemented-max-age-at-least-six-months` |
| www.google.com | Cookies | `cookie-no-secure`, `cookie-no-samesite` | `cookies-without-secure-flag-but-protected-by-hsts` |
| www.google.com | CSP | `csp-missing`, observación `csp-report-only` | `csp-not-implemented-but-reporting-enabled` |
| www.google.com | `nosniff` | `nosniff-missing` | `x-content-type-options-not-implemented` |
| wikipedia.org | Cookies | `cookie-no-samesite` | `cookies-secure-with-httponly-sessions` |
| wikipedia.org | Referrer-Policy | `referrer-policy-missing` | `referrer-policy-not-implemented`, sin penalización |

Diferencias y su causa:

- **El User-Agent cambia la respuesta de Google.** Con el User-Agent anterior del revisor, o con el de `curl`, `www.google.com` no redirigía a HTTPS ni enviaba HSTS. Con el de un navegador, redirige con 302 y envía `max-age=31536000`, como ve Observatory. El 2026-10-01 el autor decidió usar un User-Agent de navegador que termina en `AlexHerreraScanner/1.0` y la URL de la página «acerca». Con él, `www.google.com` aprueba la redirección y HSTS.
- **Cookies sin SameSite.** El revisor exige SameSite en todas las cookies; Observatory solo lo premia.
- **Cookies sin HttpOnly que no son de sesión.** El revisor las marca como informativas, sin restar puntos.
- **Referrer-Policy ausente.** Observatory no la penaliza, porque los navegadores aplican `strict-origin-when-cross-origin` por defecto. La calibración de la fase 4 decide si baja a informativa.
- **SRI.** La diferencia ya descrita en la fase 1: el revisor solo exige `integrity` a las CDN con versión fija.

### Precarga HSTS

`hstspreload.org` da como precargados 30 dominios de nivel superior, entre ellos `.app`, `.dev`, `.page`, `.bank` e `.insurance`, consultados el 2026-10-01. Un sitio bajo esos dominios aprueba HSTS y la redirección de HTTP con la observación `hsts-preloaded`, porque los navegadores solo lo abren por HTTPS. `github.io` no está precargado, así que octocat.github.io da `hsts-missing` y `http-no-redirect`.

### Puerto 80 con error

`http://twitter.com/` responde 520 desde Cloudflare. Una respuesta 4xx o 5xx por HTTP no cuenta como contenido servido sin cifrar, así que la comprobación queda sin resultado.

### Correo y DNS frente a los registros publicados

La referencia son los registros TXT y CAA que devuelve 1.1.1.1, consultados el 2026-10-01.

| Dominio | Registro publicado | Revisor |
|---|---|---|
| github.com | SPF con `ip4` e `include` de Outlook, Google y Zendesk | Aprueba `spf` |
| github.com | `v=DMARC1; p=quarantine; sp=reject; pct=100` | Aprueba `dmarc` |
| github.com | 7 registros CAA | Aprueba `caa` |
| google.com | `v=spf1 include:_spf.google.com ~all` | Aprueba `spf` |
| google.com | `v=DMARC1; p=reject` | Aprueba `dmarc` |
| google.com | 1 registro CAA, encontrado desde `www.google.com` | Aprueba `caa` |
| wikipedia.org | `v=spf1 include:_cidrs.wikimedia.org ~all` | Aprueba `spf` |
| wikipedia.org | `v=DMARC1; p=reject` | Aprueba `dmarc` |
| wikipedia.org | 3 registros CAA | Aprueba `caa` |
| alexherrera.dev | Sin registro SPF | `spf-missing` |
| alexherrera.dev | `_dmarc.alexherrera.dev` no existe | `dmarc-missing` |
| alexherrera.dev | Sin CAA en el dominio | `caa-missing` |
| twitter.com | SPF con `ip4` e `include` de Google | Aprueba `spf` |
| twitter.com | `v=DMARC1; p=reject` | Aprueba `dmarc` |
| twitter.com | Sin CAA en el dominio | `caa-missing` |

Coinciden las 15 filas.
