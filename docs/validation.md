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
