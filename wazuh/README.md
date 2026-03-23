# Wazuh Docker Certificate Generation Script/Image

This instructions are taken from the <a href="https://github.com/wazuh/wazuh-docker">Official Wazuh Docker Repo</a>. For our purposes only the first two steps are needed.

## Deploy Wazuh Docker in single node configuration

This deployment is defined in the `docker-compose.yml` file with one Wazuh manager containers, one Wazuh indexer containers, and one Wazuh dashboard container. It can be deployed by following these steps: 

1) Increase max_map_count on your host (Linux). This command must be run with root permissions:
```
$ sysctl -w vm.max_map_count=262144
```
2) Para los certificados hay que descargar:
```
$ wget https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
```
3) Dale permisos:

```
chmod +x wazuh-certs-tool.sh
```
-Ejecutar
```
./wazuh-certs-tool.sh -A
```

The environment takes about 1 minute to get up (depending on your Docker host) for the first time since Wazuh Indexer must be started for the first time and the indexes and index patterns must be generated.
