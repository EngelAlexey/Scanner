# Dependencias

Antes de instalar un paquete, anótelo aquí con su nombre exacto, quién lo mantiene y para qué sirve. Instale siempre con `pnpm install --ignore-scripts`.

| Paquete | Mantiene | Para qué sirve | Uso |
|---|---|---|---|
| `typescript` | Microsoft | Comprueba los tipos con `pnpm check`. Node 24 ejecuta el código quitando los tipos, así que no compila nada | Desarrollo |
| `@types/node` | DefinitelyTyped | Tipos de los módulos de Node 24 | Desarrollo |
| `ipaddr.js` | whitequark | Lee direcciones IPv4 e IPv6 y desenvuelve las IPv4 mapeadas. Los rangos permitidos están en tablas propias, porque su clasificación da `::7f00:1` como pública | Producción |
| `tldts` | remusao (Rémi Berson) | Lista pública de sufijos: dominio registrable para el correo y sufijos privados como `vercel.app` | Producción |

`typescript` va en la versión mayor 6, la misma del portafolio. El 2026-09-30 ya existía la 7.0.2.
