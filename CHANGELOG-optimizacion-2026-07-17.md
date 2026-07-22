# Clear NDR — Registro de cambios y optimización 

## 17. Enriquecimiento permanente por IP: empresa/sitio (2026-07-21)

**Objetivo:** que cada evento de Suricata (alertas, flows, DNS, etc.) muestre
automáticamente **a qué empresa y sitio pertenece** cada IP (`src_ip`/`dest_ip`),
usando el direccionamiento real de CIMEX y terceros.

**⚠️ Antes de empezar esta tarea se descubrió que los contenedores y volúmenes
con nombre de Clear NDR habían sido eliminados** (no por acciones de esta
sesión — lo único ejecutado antes fue `docker compose stop`). El usuario los
volvió a levantar por su cuenta; el histórico de sesiones/flows de Arkime
sobrevivió, pero **el índice de alertas de Suricata (`logstash-alert-*`)
no existía en ningún momento tras el reinicio** — pendiente de confirmar si
es porque aún no dispara una alerta nueva o si ese índice específico no se
recuperó. No bloqueó este trabajo porque el enriquecimiento aplica a eventos
futuros, no depende del histórico.

**Fuente de datos:** 20 archivos Excel en `~/Descargas/Enlaces Empresas
3ras.xlsx` y `~/Descargas/Enlaces y direccionado/` (por provincia + Habana +
resúmenes generales de WAN/LAN/servidores) — un export de aprovisionamiento
de un operador con **decenas de entidades estatales cubanas** (CIMEX es la
mayor con ~3,388 rangos, pero también ETECSA, MINSAP, BANDEC, Correos,
Educación, Poder Popular Provincial, y más).

**Procesamiento** (`/tmp/.../scratchpad/parse_ip_directory_v2.py` +
`consolidate_final.py`, no committeados a ningún repo):
1. Parser genérico (detecta columnas de IP/nombre por contenido, no por
   posición fija) sobre los 20 archivos → 24,938 registros crudos.
2. Resolución de conflictos por prioridad explícita (confirmada con el
   usuario): archivos por provincia > `Enlaces Empresas 3ras` > archivos
   generales (`WAN y LAN CIMEX`, `SERV CIMEX`, `CIMEX3-GAE`) — estos últimos
   solo rellenan huecos. Bajó 24,938 → **10,195 rangos únicos**.
3. Salida: `ip_directory_final.json`, array ordenado por IP de inicio
   (`{start, end, cidr, empresa, sitio}`, enteros de 32 bits) para permitir
   búsqueda binaria — 1.4MB.

**Por qué NO se hizo en OpenSearch directamente:** se probó crear una
política de "Enrich" (`PUT /_enrich/policy/...`, el mecanismo nativo de
Elasticsearch para este caso exacto) y OpenSearch respondió
`no handler found for uri` — **OpenSearch nunca portó el Enrich Processor de
Elasticsearch**, no es una opción viable en este motor.

**Solución real: plugin propio de Fluentd**, seleccionado porque Fluentd ya
usa exactamente este patrón para otra cosa: hay dos filtros `geoip`
(`src_ip` y `dest_ip`) haciendo lookups por IP antes de indexar. Se agregó
un tercer par de filtros con el mismo patrón, pero con un plugin propio:

- `events-stack/fluentd/plugins/filter_ip_directory.rb` — filtro Fluentd
  (`Fluent::Plugin::Filter`) que carga el JSON una vez al arrancar y hace
  **búsqueda binaria** (no lineal) sobre las 10,195 entradas ordenadas;
  incluye un escaneo acotado hacia atrás (máx. 200 entradas) para elegir el
  rango **más específico** cuando hay anidamiento (ej. un pool `/23`
  "SEGMENTS" que contiene un circuito `/30` puntual).
- `events-stack/fluentd/ip_directory.json` — los datos (1.4MB, demasiado
  grande para un `configs:` de Docker, que tiene un límite de 500KB — se
  montó como bind-mount normal en su lugar).
- `fluent.conf`: dos filtros nuevos (`@type ip_directory`, uno por
  `lookup_key src_ip`/`field_prefix src` y otro por `dest_ip`/`dst`),
  agregados justo después de los de `geoip` existentes.
- `events-stack.compose.yaml`, servicio `fluentd`: se agregó `-p
  /fluentd/etc/plugins` al `command:` (para que Fluentd cargue el plugin
  propio) y dos `volumes:` nuevos (el `.rb` y el `.json`, ambos `:ro`).

**Campos que agrega a cada evento** (cuando hay match): `empresa_src`,
`sitio_src`, `ip_directory_cidr_src` (y el mismo trío con `_dst` para
`dest_ip`). Sin match, no agrega nada (mismo comportamiento que `geoip` con
`skip_adding_null_record`).

**Verificado con un evento sintético** inyectado directo en el `eve.json`
que tailea Fluentd (`src_ip: 172.19.220.230`, dentro de `172.19.220.224/28`):
llegó a OpenSearch con `empresa_src: "CORPORACION CIMEX S.A."`, `sitio_src:
"Cimex-Tienda La Central"` — el IP de destino (`8.8.8.8`, fuera del
direccionamiento) correctamente no llevó ningún campo `_dst`.

**⚠️ Mismo riesgo de reversión silenciosa que las secciones 3 y 13:** estos
cambios (el `command:` con `-p`, los dos `volumes:` nuevos) no están
respaldados por ninguna clave de `values.yaml`/`*.config.yaml` — si algún
día `stamusctl compose update` regenera `events-stack.compose.yaml` desde
cero, estos cambios se perderían igual que pasó con el heap de OpenSearch.
No hay una clave de schema para esto todavía; si se vuelve a perder, revisar
primero esta sección antes de volver a investigar desde cero.

---

## Contenedores recreados durante la sesión

`opensearch`, `suricata` (x2), `scirius` (x2), `fluentd` (sección 17) — cada
recreación se verificó con `docker inspect` (estado `healthy`) o logs de
arranque antes de continuar.
