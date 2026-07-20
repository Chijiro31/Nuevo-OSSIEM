# Clear NDR — Registro de cambios y optimización (2026-07-13 a 2026-07-19)

Este documento resume todos los cambios aplicados a este despliegue de Clear NDR
durante la sesión de revisión/optimización, con el motivo de cada uno. Las secciones
11 y 12 cubren la integración posterior con el stack SOCFortress CoPilot (SIEM
Wazuh/Graylog) y con Clear NDR como fuente de alertas de Suricata.

---

## 1. Bug de validación de contraseña al crear/editar usuarios

**Archivo:** `accounts/rest_api.py` (parcheado, ver sección 6 para persistencia)

**Qué se cambió:**
```python
# Antes
password_validation.validate_password(password=password, user=User)

# Después (creación de usuario, AccountSerializer.create)
password_validation.validate_password(password=password, user=User(**user_data))

# Después (cambio de contraseña de otro usuario, ChangePasswordSuperUserSerializer)
target_user = User.objects.filter(pk=self.initial_data.get('user')).first()
password_validation.validate_password(password=password, user=target_user)
```

**Por qué:** se le pasaba la **clase** `User` en vez de una instancia real al validador
`UserAttributeSimilarityValidator`. Ese validador necesita leer `username`/`email` reales
para comparar contra la contraseña; al recibir la clase, la comparación nunca se
ejecutaba — **sin lanzar error, en silencio**. Efecto real: se podía crear un usuario o
cambiarle la contraseña a un valor idéntico o muy parecido a su propio username, algo que
la política de contraseñas debería rechazar. Confirmado con una prueba reproducible
(`networkadmin`/`networkadmin` era aceptado antes del fix, rechazado después).

---

## 2. Logout forzado repetido para el rol "User" (caso rolando123)

**Diagnóstico:** no era un bug de sesión, cookies, ni de Scirius — se descartó con
evidencia (sesiones sanas en BD, cookie de login emitida correctamente, 0 errores en
logs de Scirius/Scout/nginx). La causa real: el rol **"User"** solo tenía permisos de
**lectura** (`configuration_view, events_evebox, events_kibana, events_view,
ruleset_policy_view, source_view`). Al faltarle permisos de edición, **Scout** recibía
`403` de la API de Scirius en alguna acción y, en vez de mostrar "acceso denegado", lo
interpretaba como sesión inválida y forzaba un logout completo del usuario.

**Cambios aplicados:**
- Se creó un rol nuevo **`Analyst`** (editable desde la UI, a diferencia de los roles
  default `Superuser`/`Staff`/`User` que Scirius bloquea para edición) con permisos:
  `configuration_view`, `configuration_edit`, `source_view`, `source_edit`,
  `ruleset_policy_view`, `ruleset_policy_edit`, `events_view`, `events_edit`,
  `events_kibana`, `events_evebox`.
  - **Deliberadamente sin** `configuration_auth` (permiso de super-admin) ni
    `ruleset_update_push` (no era necesario para resolver el bug).
- Se reasignó al usuario (creado como `rolando123`, luego renombrado a `123WER`, mismo
  ID interno) del rol `User` al rol `Analyst`.
- Se limpiaron roles duplicados creados durante las pruebas (`rolando`, `analisty`).
- El usuario `clearndr34` (que había quedado sin rol tras borrar `rolando`) se asignó
  también a `Analyst`.
- El rol `User` compartido quedó **revertido a su estado original** (solo lectura) — el
  fix vive en el rol nuevo, no en el default.

**Por qué el fix en un rol nuevo y no en "User":** los roles default (`Superuser`,
`Staff`, `User`) tienen los permisos bloqueados/deshabilitados en la UI de Scirius
(`GroupEditForm.DEFAULT_GROUPS`). Modificar permisos ahí solo se puede hacer por consola,
y no queda editable a futuro desde la interfaz. Crear un rol nuevo deja todo manejable
desde la UI de aquí en adelante.

---

## 3. OpenSearch: heap de la JVM `2g → 8g`

**Archivo:** `events-stack/events-stack.compose.yaml` (`OPENSEARCH_JAVA_OPTS`) y
`values.yaml` (`opensearch.memory`)

**Por qué:** OpenSearch usaba 61% de CPU con un heap fijo de solo 2GB, muy por debajo de
lo que el host puede ofrecer (30GB RAM, 8 cores). Un heap tan chico fuerza garbage
collection constante bajo carga. Tras subir a 8GB, el uso de CPU bajó a ~31% en la misma
carga — confirmado con `docker stats` antes/después.

---

## 4. Suricata: interfaz de captura `docker0 → wlp0s20f3`

**Archivo:** `suricata/suricata.compose.yaml` (`SURICATA_OPTIONS`) y `values.yaml`
(`suricata.interfaces`)

**Por qué:** Suricata estaba configurado para monitorear `docker0`, la interfaz puente
por defecto de Docker. En este host esa interfaz está **caída** (`NO-CARRIER`) — no es el
bridge que usan los contenedores del stack (usan bridges personalizados de Compose).
Verificado con las estadísticas en vivo de Suricata: `kernel_packets: 0` — Suricata
corría sano pero sin analizar ni un solo paquete. Se cambió a `wlp0s20f3` (el adaptador
WiFi real de la máquina) para que efectivamente inspeccione tráfico real.

---

## 5. Endurecimiento de seguridad en Scirius (`local_settings.py`)

**Qué se cambió:**
```python
# Antes
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
CSRF_TRUSTED_ORIGINS = ["http://localhost:8000", "http://localhost:5173"]
CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOWED_ORIGINS = ['http://localhost:5173', 'http://localhost:8000', ...]

# Después
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in os.getenv('DEPLOYMENT_ORIGINS', "https://10.254.194.100").split(',')]
CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv('DEPLOYMENT_ORIGINS', "https://10.254.194.100").split(',')]
```

**Por qué:** el archivo `local_settings.py`, que viene dentro de la imagen
`clear-ndr-1.1.2` y se importa **al final** de `settings.py` (sobreescribiendo todo lo
anterior), traía valores de **desarrollo** hardcodeados en un despliegue que corre en
producción sobre HTTPS real:
- `*_SECURE = False`: las cookies de sesión/CSRF podían viajar sin exigir HTTPS.
- `CORS_ORIGIN_ALLOW_ALL = True` combinado con `CORS_ALLOW_CREDENTIALS = True`: esto es lo
  más serio — permitía que **cualquier sitio web** hiciera peticiones autenticadas a la
  API de Scirius usando las cookies de sesión de quien tuviera el panel abierto en el
  navegador (riesgo de robo de datos/acciones vía CSRF-por-CORS).
- Los orígenes confiables apuntaban a `localhost:8000`/`localhost:5173` (servidor de
  desarrollo Vite/Django), irrelevantes para este despliegue.

Se usa la variable de entorno `DEPLOYMENT_ORIGINS` (nueva, ver más abajo) en vez de
hardcodear la IP directamente en el `.py`, justamente por el problema de IP dinámica
descrito en la sección 8.

---

## 6. Persistencia de los parches de Scirius vía `configs:`

**Archivo:** `scirius/scirius.compose.yaml`

**Qué se cambió:** se agregaron dos entradas al bloque `configs:` (el mismo mecanismo que
ya usaba este stack para inyectar `start-scirius.sh`), montando:
- `patches/rest_api.py` → `/code/accounts/rest_api.py`
- `patches/local_settings.py` → `/code/scirius/local_settings.py`

**Por qué:** el primer parche de `rest_api.py` (sección 1) se había aplicado originalmente
copiando el archivo directamente dentro del contenedor en ejecución (`docker cp`). Eso
solo modifica la capa de escritura del contenedor — **se pierde si el contenedor se
recrea** (actualización de imagen, `docker compose up` con cambios, etc.). Migrar ambos
parches a `configs:` los deja persistentes: sobreviven a cualquier recreación del
contenedor mientras los archivos existan en `scirius/patches/` en el host.

---

## 7. Retención de datos: política ISM `15d → 45d`

**Dónde:** política ISM `hot_warm_delete` en OpenSearch (aplicada vía API `_plugins/_ism`)
y `values.yaml` (`opensearch.ism.delete_min_index_age`)

**Por qué:** con 417GB libres de 468GB de disco, 15 días de retención era muy
conservador. Se subió el umbral de borrado (transición `warm → delete`) a 45 días. La
transición `hot → warm` se dejó en 7 días (eso solo afecta a que el índice pase a
solo-lectura para liberar recursos de escritura, no borra nada).

---

## 8. Corrección de IP dinámica del host (DHCP)

**Contexto:** durante las pruebas, la IP de la máquina cambió de `10.128.235.100` a
`10.254.194.100` (el adaptador WiFi renovó el lease DHCP a otra subred). Esto no fue un
cambio nuestro, pero **rompió** el endurecimiento de CORS/CSRF de la sección 5 apenas
aplicado, porque los orígenes confiables habían quedado hardcodeados a la IP vieja
(hubiera causado fallos de login por CSRF).

**Fix:** en vez de hardcodear la IP dentro del `.py`, se agregó la variable de entorno
`DEPLOYMENT_ORIGINS` en `scirius/scirius.compose.yaml`:
```yaml
- DEPLOYMENT_ORIGINS=https://10.254.194.100 #comma-separated list, update if the host IP changes (DHCP)
```
Así, si la IP vuelve a cambiar, solo hay que editar esa línea del compose (y recrear el
contenedor de Scirius), sin tocar el archivo Python parcheado.

**Recomendación pendiente:** si esta máquina sigue recibiendo IPs distintas por DHCP,
conviene fijar una IP estática o usar un hostname para el panel, en vez de depender de la
IP dinámica de la WiFi.

---

## 9. Filtro de reglas de Suricata

**Qué se cambió:** se quitaron 4 categorías del ruleset activo (`Default ruleset`, vía
`Ruleset.categories`, y se disparó la tarea `UpdateGenerateRuleset` para regenerar y
recargar en caliente):
- `emerging-deleted` — reglas que Emerging Threats marcó como retiradas/reemplazadas.
- `emerging-retired` — mismo caso.
- `emerging-scada` — reglas de sistemas de control industrial (SCADA/ICS).
- `emerging-mobile_malware` — malware específico de dispositivos móviles.

**Resultado:** 50,771 → 49,149 reglas activas.

**Por qué esas 4 y no otras:**
- `deleted`/`retired`: ruido puro sin valor de detección, ET ya no las mantiene — recorte
  seguro sin excepción.
- `scada`/`mobile_malware`: se confirmó contigo explícitamente que esta red **no tiene**
  sistemas SCADA/ICS ni se monitorea tráfico de dispositivos móviles, así que esas firmas
  nunca van a disparar una detección real — es puro costo (CPU/reglas cargadas) sin
  beneficio.
- Se dejaron activas otras categorías chicas candidatas (VOIP, Telnet, P2P, Juegos, Chat)
  porque decidiste no descartarlas.
- **No se tocaron** las categorías grandes de alto valor de detección (`emerging-malware`,
  `emerging-web_specific_apps`, etc.) — reducirlas hubiera bajado el conteo de reglas
  mucho más, pero a costa de cobertura real de detección.

---

## 10. Buffer de captura de Suricata (ring-size / block-size)

**Archivo:** `containers-data/suricata/etc/suricata.yaml`, sección `af-packet` →
`interface: default` (la que aplica a `wlp0s20f3`, ya que no hay una entrada explícita
para esa interfaz)

**Qué se cambió:**
```yaml
- interface: default
  #threads: auto
  #tpacket-v3: yes
  ring-size: 20000
  block-size: 1048576
```

**Por qué — el hallazgo más crítico de toda la sesión:** después del cambio de interfaz
(sección 4), se detectó que Suricata estaba **descartando ~64% de los paquetes**
(`kernel_drops: 1,164,861` de `kernel_packets: 1,827,220`). El buffer de captura
(ring/bloques AF_PACKET) tenía un tamaño por defecto muy pequeño (324 frames por hilo,
~4MB de memoria total entre los 8 hilos) para el volumen real de tráfico de esta interfaz.
Con 64% de pérdida, **no importaba cuántas reglas tuviera cargadas** — la mayoría del
tráfico ni siquiera llegaba al motor de detección.

Se subió el tamaño del ring a 20,000 frames por hilo (~32MB por hilo, ~260MB total entre
los 8 hilos — margen amplio dado que el host tiene 30GB de RAM). Tras el cambio y
reinicio del contenedor, se verificó:
- Justo después de reiniciar: 0 drops.
- Tras ~2 minutos de tráfico real: 0 drops sobre miles de paquetes.
- Tras ~10 minutos sostenidos: **0.000% de pérdida** sobre 108,028 paquetes.

---

## 11. CoPilot (SOCFortress) — Pipeline de alertas Wazuh EDR → SIEM/Alerts

Trabajo en un stack separado (SOCFortress CoPilot: Wazuh, Graylog, Velociraptor,
MySQL, MinIO — repo en `~/Descargas/Prueba-main`), instalado en la misma máquina.
La sección "SIEM/Alerts" de CoPilot no mostraba ninguna alerta real a pesar de que
Wazuh sí estaba generando alertas.

**Diagnóstico (cadena de causas reales, no la primera hipótesis):**
1. El input de Graylog "WAZUH EVENTS FLUENT BIT - TCP" aparecía en NOT RUNNING —
   se resolvió haciéndolo `global: true` en vez de node-scoped, sin tocar el
   `fluentbit.conf` de Wazuh (instrucción explícita: no tocar esa configuración).
2. La búsqueda de Graylog fallaba con `JSON.parse` — causa real: el certificado TLS
   del nodo de Graylog no tenía el SAN correcto para la IP externa registrada
   (`10.254.194.100`). Se regeneró el certificado con el SAN completo y se
   reconstruyó el truststore.
3. Ya con eventos entrando, "SIEM/Alerts" seguía vacío. La función de CoPilot
   que recolecta alertas (`return_graylog_events_index_names`) **no lee Streams
   de Graylog en absoluto** — busca directamente en el clúster OpenSearch del
   Wazuh Indexer (172.28.0.20) índices con alias `gl-events*`. Ese índice nunca
   existía porque Graylog guarda sus propios datos en un OpenSearch separado
   (172.28.0.11).
4. Se intentó apuntar Graylog directamente al OpenSearch del Wazuh Indexer para
   que escribiera ahí — **se revirtió**: el cliente ES7 que trae Graylog 7.1.1
   falla con `NullPointerException` al hacer bulk indexing contra ese clúster
   (incompatibilidad de librería, no de configuración).

**Solución final — `alert-bridge` (contenedor nuevo, Python, HTTP plano, sin
pasar por el cliente ES de Graylog):**
- Lee las alertas nativas de Wazuh (`wazuh-alerts-4.x-*`) cada 30s.
- Resuelve `customer_code` (fijo a `aster` en este entorno vía
  `DEFAULT_CUSTOMER_CODE`, único cliente provisionado).
- Escribe un documento tipo "Event" de Graylog en **`gl-events-<customer_code>-0`**
  (ej. `gl-events-aster-0`) con `fields.COPILOT_ALERT_ID: "NONE"` — el sentinel
  que CoPilot busca para saber qué alertas le faltan crear.
- `origin_context` **autorreferenciado** (apunta al propio documento del bridge,
  no al alert original de Wazuh) — necesario porque CoPilot solo lee campos
  planos de nivel superior, y porque el filtro de "Customer" en la UI compara
  el **nombre del índice de origen** contra el código/nombre del cliente como
  substring; `wazuh-alerts-4.x-*` es compartido entre todos los clientes y
  nunca lo cumple, mientras que `gl-events-aster-0` sí.
- Se ajustó la configuración de CoPilot (`incident_management_fieldname` /
  `assetfieldname` / `timestampfieldname` / `alerttitlefieldname`,
  `event_sources`) para el `source='wazuh'`, mapeando `agent_name`,
  `rule_description`, `timestamp`, `customer_code` como campos planos.

**Resultado:** 183 alertas reales creadas en `incident_management_alert`
(178 de Wazuh en el primer barrido), visibles en SIEM/Alerts filtrando por
Customer = aster, sin errores en el log del scheduler (`invoke_alert_creation_collect`,
cada 5 min).

**Restricción respetada durante toda la sesión:** no se modificó
`wazuh/config/fluentbit/fluentbit.conf` en ningún momento — toda la solución
vive del lado de Graylog/OpenSearch y en el nuevo contenedor `alert-bridge`.

---

## 12. Integración Clear NDR (Suricata) → CoPilot

Con el pipeline de Wazuh funcionando, se extendió el mismo `alert-bridge` para
también traer las alertas de Suricata (Clear NDR) al mismo SIEM/Alerts de
CoPilot, reutilizando toda la infraestructura de la sección 11.

**Qué se cambió:**
- Red: el contenedor `alert-bridge` se conectó también a la red Docker de
  Clear NDR (`clearndr-ndKjZZo5ikOs77ca`), además de `siem-net` — sin exponer
  puertos ni tocar la configuración de ninguno de los dos stacks.
- `alert-bridge/bridge.py`: se agregó una segunda fuente de lectura contra el
  OpenSearch de Clear NDR (`config-opensearch-ndKjZZo5ikOs77ca:9200`, sin auth
  — tiene `plugins.security.disabled=true`), leyendo el índice
  `logstash-alert-*` (donde Fluentd deposita los eventos `event_type: alert`
  de Suricata), filtrando por `alert.severity <= 2` (severidad de Suricata va
  1=más crítico a 3=menos, al revés que Wazuh).
- Cada alerta de Suricata se transforma al mismo formato de Event
  (`ALERT_SOURCE: "suricata"`, `rule_description` = `alert.signature`,
  `src_ip` como campo de "asset", `origin_context` autorreferenciado igual
  que en la sección 11) y se escribe en el **mismo índice por cliente**
  `gl-events-aster-0`.
- CoPilot: se dio de alta un `event_source` para Suricata (`customer_code=aster,
  event_type=NDR`) y el mapeo `source='suricata'` en las tablas
  `incident_management_*fieldname` (`assetfieldname: src_ip`,
  `alerttitlefieldname: rule_description`, `timestampfieldname: timestamp`).

**Resultado:** confirmado con una alerta real ("ET DNS Query to a *.top domain -
Likely Hostile") creada en `incident_management_alert` sin errores. Verificado
que, pidiendo suficientes resultados para cubrir todo el índice, la vista
filtrada por Customer = aster muestra ambas fuentes juntas (380 alertas de
Wazuh + 6 de Suricata en el momento de la prueba).

**Documentación de arquitectura completa:** `~/config/INTEGRACION-CLEARNDR-COPILOT.md`.

---

## Resumen de archivos tocados

| Archivo | Cambio |
|---|---|
| `accounts/rest_api.py` (parche) | Fix validación de contraseña |
| `scirius/patches/rest_api.py` | Copia persistente del parche anterior |
| `scirius/patches/local_settings.py` | Endurecimiento CORS/CSRF/cookies |
| `scirius/scirius.compose.yaml` | Monta ambos parches vía `configs:`, agrega `DEPLOYMENT_ORIGINS` |
| `events-stack/events-stack.compose.yaml` | `OPENSEARCH_JAVA_OPTS` heap 2g→8g |
| `suricata/suricata.compose.yaml` | `SURICATA_OPTIONS` interfaz `docker0`→`wlp0s20f3` |
| `containers-data/suricata/etc/suricata.yaml` | `ring-size`/`block-size` af-packet |
| `values.yaml` | `opensearch.memory`, `opensearch.ism.delete_min_index_age`, `suricata.interfaces` |
| Base de datos (Django ORM) | Rol `Analyst` creado, permisos, reasignación de usuarios, categorías del ruleset, política ISM |

## Contenedores recreados durante la sesión

`opensearch`, `suricata` (x2), `scirius` (x2) — cada recreación se verificó con
`docker inspect` (estado `healthy`) antes de continuar.
