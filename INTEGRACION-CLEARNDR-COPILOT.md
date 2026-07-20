# Integración Clear NDR ↔ CoPilot (SOCFortress)

**Estado: implementado y funcionando.** Este documento describe la arquitectura
real de cómo las alertas de Suricata (Clear NDR / SELKS) llegan al mismo
"SIEM/Alerts" de CoPilot donde ya llegan las alertas de Wazuh EDR, y sirve como
referencia para extender el mismo patrón a otras fuentes o clientes.

Fecha de implementación: 2026-07-19

## 1. Arquitectura: dos stacks, un solo bridge

Los dos stacks corren en el mismo host, en **redes Docker separadas**, sin
conocerse entre sí de forma nativa:

| Stack | Red Docker | Contenedores clave |
|---|---|---|
| **Clear NDR** (Stamus/SELKS) | `clearndr-ndKjZZo5ikOs77ca` (172.19.0.0/16) | `config-suricata-...` (host network), `config-scirius-...` (172.19.0.4), `config-opensearch-...` (172.19.0.10, **sin auth**), `config-fluentd-...` (172.19.0.8) |
| **CoPilot** (SOCFortress) | `siem-net` (172.28.0.0/24) | `wazuh-indexer` (172.28.0.20), `graylog-server` (172.28.0.12), `copilot-backend` (172.28.0.51), **`alert-bridge` (172.28.0.71)** |

El contenedor `alert-bridge` está conectado a **ambas redes** (`siem-net` +
`clearndr-ndKjZZo5ikOs77ca`) y es el único punto de contacto entre los dos
stacks. No se expuso ningún puerto al host ni se modificó la configuración
interna de ninguno de los dos stacks para lograr esto.

```
Suricata (eve.json, host network)
    │
    ▼
Fluentd (config-fluentd-...) ── separa eve.json por event_type
    │
    ▼
OpenSearch Clear NDR (config-opensearch-..., :9200, sin auth)
    índice: logstash-alert-YYYY.MM.DD  (event_type: "alert")
    │
    │   ══════════ alert-bridge (único puente entre stacks) ══════════
    │   - polling cada 30s a ambas fuentes (Wazuh y Suricata)
    │   - filtra por severidad (Wazuh: rule.level >= 3; Suricata: severity <= 2)
    │   - normaliza a un "Event" de Graylog con campos planos
    │   - origin_context AUTORREFERENCIADO (ver sección 3)
    ▼
gl-events-aster-0  (en el clúster OpenSearch del Wazuh Indexer, 172.28.0.20)
    fields.ALERT_SOURCE: "wazuh" | "suricata"
    fields.COPILOT_ALERT_ID: "NONE"  ← sentinel de "pendiente de crear"
    │
    ▼
CoPilot backend (invoke_alert_creation_collect, cada 5 min)
    busca fields.COPILOT_ALERT_ID == "NONE" en índices "gl-events*"
    ▼
incident_management_alert (MySQL) ──► UI "SIEM/Alerts" (filtro Customer=aster)
```

Wazuh y Suricata terminan en el **mismo índice** (`gl-events-aster-0`) porque
ambos pertenecen al mismo cliente (`aster`, único cliente provisionado en este
entorno) — el índice es por-cliente, no por-fuente.

## 2. Por qué esta arquitectura (y no otras que no funcionaron)

- **Graylog no interviene en la escritura.** Se probó apuntar Graylog
  directamente al OpenSearch del Wazuh Indexer para que reindexara ahí — el
  cliente ES7 que trae Graylog 7.1.1 falla con `NullPointerException` al hacer
  bulk indexing contra un clúster que no es el suyo propio (incompatibilidad
  de librería). El bridge escribe por HTTP plano (`requests`), sin pasar por
  el cliente de Graylog en absoluto.
- **CoPilot no lee Streams de Graylog para el auto-creation de alertas.** Lee
  directamente índices con alias `gl-events*` en el clúster del Wazuh Indexer
  (función `return_graylog_events_index_names`). Por eso el bridge escribe
  ahí en vez de a Graylog.
- **El índice debe contener el `customer_code`/`customer_name` en el
  nombre.** El filtro de "Customer" en la UI de CoPilot compara el nombre del
  índice de **origen** (resuelto vía `origin_context`) contra el código del
  cliente como substring — no compara ningún campo de texto. Por eso el
  índice se llama `gl-events-aster-0` y no algo genérico como
  `gl-events-wazuh-0`.
- **No se puede usar el prefijo `gl-events` a secas** al crear índices vía la
  API de Graylog — está reservado por su motor interno de Events/Alerting.
  Escribir directo a OpenSearch (sin pasar por la API de Graylog) evita ese
  problema.
- **`origin_context` es autorreferenciado**: apunta al propio documento que
  el bridge escribe en `gl-events-aster-0`, no al alert original en
  `wazuh-alerts-4.x-*` / `logstash-alert-*`. Esto es necesario porque CoPilot
  solo lee campos planos de primer nivel (sin rutas con punto), y porque así
  el documento que CoPilot termina leyendo siempre tiene el nombre de índice
  correcto para el filtro de cliente.

## 3. Implementación real (`alert-bridge/bridge.py`)

Un solo contenedor (`alert-bridge`), un solo archivo Python, dos fuentes:

- `es()` / `SESSION` → clúster del Wazuh Indexer (172.28.0.20, con auth) —
  aquí viven tanto `wazuh-alerts-4.x-*` como el índice de destino
  `gl-events-aster-0`.
- `clearndr_es()` / `CLEARNDR_SESSION` → OpenSearch de Clear NDR
  (`config-opensearch-ndKjZZo5ikOs77ca:9200`, sin auth).

Funciones por fuente (mismo patrón, distinta fuente de lectura):

| | Wazuh | Suricata |
|---|---|---|
| Índice de lectura | `wazuh-alerts-4.x-*` | `logstash-alert-*` |
| Filtro de severidad | `rule.level >= MIN_ALERT_LEVEL` (default 3) | `alert.severity <= MAX_SURICATA_SEVERITY` (default 2, **invertido**: 1=crítico) |
| Función fetch | `fetch_new_wazuh_alerts` | `fetch_new_suricata_alerts` |
| Función write | `write_graylog_event` | `write_suricata_event` |
| `fields.ALERT_SOURCE` | `"wazuh"` | `"suricata"` |
| Campo "asset" | `agent_name` | `src_ip` |
| Campo "título" | `rule_description` (= `rule.description`) | `rule_description` (= `alert.signature`) |

Ambas funciones de escritura comparten el helper `index_event(gl_index,
event_id, gl_event)`, que asegura que el índice por-cliente exista (con su
alias, requerido para que `gl-events*` lo detecte — ver sección 4) y escribe
el documento.

El loop principal (`run()`) recorre ambas fuentes en cada ciclo de 30s, cada
una en su propio `try/except` — si Clear NDR está caído, Wazuh se sigue
bridgeando igual y viceversa.

## 4. Configuración del lado CoPilot (ya aplicada)

- **`event_sources`**: fila `customer_code='aster', name='Suricata',
  index_pattern='gl-events-aster-0', event_type='NDR'`.
- **Mapeo de campos** en `incident_management_*fieldname` para
  `source='suricata'`:

  | Tabla | field_name |
  |---|---|
  | `incident_management_assetfieldname` | `src_ip` |
  | `incident_management_timestampfieldname` | `timestamp` |
  | `incident_management_alerttitlefieldname` | `rule_description` |
  | `incident_management_fieldname` | `dest_ip` (contexto opcional) |

  No se creó un `connector` dedicado para Suricata — el bridge no pasa por la
  capa de conectores de CoPilot, así que no es necesario.

## 5. Verificación

- El scheduler de CoPilot (`invoke_alert_creation_collect`, cada 5 min) creó
  la alerta "ET DNS Query to a *.top domain - Likely Hostile" en
  `incident_management_alert` sin errores.
- Consultando `/api/alerts/alerts/graylog` con `customer_codes:["aster"]` y
  tamaño de página suficiente para cubrir todo el índice, aparecen **ambas
  fuentes juntas**: 380 alertas `ALERT_SOURCE: wazuh` + 6 `ALERT_SOURCE:
  suricata`.
- ⚠️ Con tamaños de página chicos (ej. 50) puede que solo se vean alertas de
  Wazuh, simplemente porque son la mayoría y la consulta no aplica un `sort`
  explícito — no es un bug, es orden interno de Elasticsearch.

## 6. Cómo extender esto a una fuente o cliente nuevo

1. Si es una fuente nueva (ej. otro NDR/EDR): agregar un par de funciones
   `fetch_new_<fuente>_alerts` / `write_<fuente>_event` en `bridge.py`,
   siguiendo el patrón de la tabla de la sección 3, y sumarlas al loop de
   `run()` con su propio `try/except`.
2. Si es un cliente nuevo (ej. `acme` además de `aster`): no hace falta tocar
   `bridge.py` — `gl_index_for(customer_code)` ya genera el nombre de índice
   por cliente automáticamente (`gl-events-acme-0`). Solo hay que:
   - Que `get_customer_code(...)` (Wazuh) resuelva el código correcto por
     cliente, o pasar un `DEFAULT_CUSTOMER_CODE` distinto si el bridge corre
     una instancia por cliente.
   - Dar de alta el `event_source` y el mapeo de `incident_management_*fieldname`
     para ese cliente/fuente en CoPilot (puede reusar el mismo `source` si el
     formato de datos es igual).
3. Repetir la verificación de la sección 5 con el `customer_code` nuevo.
