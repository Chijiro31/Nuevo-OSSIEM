# Wazuh Docker Certificate Generation Script/Image

Estas instrucciones están tomadas del Repositorio Oficial Docker de Wazuh. Para nuestros propósitos, solo se necesitan los dos primeros pasos.

### Despliega Wazuh Docker en configuración de nodo único

Este despliegue está definido en el archivo con un contenedor gestor Wazuh, un contenedor indexador Wazuh y un contenedor dashboard Wazuh. Se puede desplegar siguiendo estos pasos:docker-compose.yml

1) Aumenta max_map_count en tu host (Linux). Este comando debe ejecutarse con permisos root:
```
$ sysctl -w vm.max_map_count=262144
```
2) Ejecuta el script de creación de certificados:
```
$ docker-compose -f generete-indexer-certs.yml run --rm generator
```
3) Comienza el entorno con docker-compose:
 - En el antegrama:
 ```
$ docker-compose up
```
- De fondo:
```
$ docker-compose up -d
```

El entorno tarda aproximadamente 1 minuto en activarse (dependiendo de tu host Docker) por primera vez, ya que Wazuh Indexer debe iniciarse por primera vez y generar los índices y patrones de índices.
