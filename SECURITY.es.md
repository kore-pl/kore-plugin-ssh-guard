# Divulgación de vulnerabilidades de seguridad

Este archivo describe el proceso de divulgación de vulnerabilidades de este repositorio de complementos (id `ssh-guard`); no es un documento de diseño de seguridad.

## Alcance

Cubre: la implementación de `SSH 加固插件` (id `ssh-guard`), la declaración de capacidades en `info.json`, el front-end `web/` y los artefactos de `make dist`.

No cubre: problemas del núcleo y del protocolo — repórtalos según [SECURITY.md de kore](https://github.com/kore-pl/kore/blob/main/SECURITY.md); las vulnerabilidades conocidas de dependencias externas también deben comunicarse al proyecto upstream.

## Versiones compatibles

| Versión | Estado | Notas |
| --- | --- | --- |
| `0.4.0` (última actual) | ✅ Aceptada y corregida | Las correcciones de seguridad se aplican solo a la última versión de parche |
| Versiones `0.x` anteriores | ❌ Sin soporte | Actualiza primero a la última versión |

Durante `0.x` el soporte es mínimo: solo la versión de parche más reciente de una línea minor recibe correcciones; no se respaldan parches anteriores.

## Superficie de ataque de este repositorio

- **Métodos RPC**: todos los métodos `ssh-guard.*` (ver `README.md`); la falta de validación de parámetros puede provocar escalada de privilegios o inyección.
- **capabilities**: `info.json.capabilities` es la superficie completa de autorización del complemento; cada declaración adicional es otra vía de ataque.
- **Proceso independiente y UDS**: el complemento se ejecuta como proceso independiente; el socket lo crea el shell anfitrión, con `chown kore-<id>` y permiso `0600`; eludir los permisos del socket o conectarse al socket de otro complemento es una vulnerabilidad.
- **Superficie de escritura en el host**: cualquier escritura fuera de las capabilities realmente concedidas (archivos / procesos / red / base de datos) es una vulnerabilidad.
- **Front-end**: `web/` se ejecuta en un iframe de origen separado y se comunica con el shell mediante postMessage; XSS, falsificación de mensajes y lectura de datos de otros complementos son problemas de la frontera de seguridad.

## Cómo informar

1. **Prefiere un Security Advisory de GitHub**: página de Security de este repositorio → "Report a vulnerability" (canal privado, sin issue público).
2. **Correo alternativo**: `pengtang1024@users.noreply.github.com`, asunto `[kore security] ssh-guard`.
3. **No abras issues públicos ni pegues PoCs en discusiones o PR.**
4. Incluye: versión afectada, pasos de reproducción o PoC, evaluación del impacto, si ya es pública y preferencia de crédito.

## Plazos y divulgación

- Confirma la recepción y da una primera valoración en un plazo de **72 horas**; los problemas complejos reciben un plan posterior.
- Coordina la divulgación tras la corrección, con una ventana predeterminada de **90 días**; consulta primero si el problema se está explotando activamente.
- Registra las correcciones de seguridad en `CHANGELOG.md` tras el lanzamiento (sin detalles de explotación) y publica un aviso de seguridad si procede.

## Agradecimientos

El crédito se da en las notas de lanzamiento con el consentimiento del informante; anónimo si se solicita.
