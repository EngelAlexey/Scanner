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
