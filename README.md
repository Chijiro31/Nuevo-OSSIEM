## Pre-despliegue
El primer paso es construir la imagen del Custom Wazuh Manager usando el script de compilación proporcionado en wazuh/custom-wazuh-manager, allí encontrarás las instrucciones para la compilación.
A continuación, tienes que crear, por el medio que prefieras, los certificados SSL de Wazuh requeridos y colocarlos en el directorio wazuh/config/wazuh_indexer_ssl_certs. Estoy proporcionando la generación oficial de certificados de Wazuh Escritura bajo Wazuh/generate-indexer-certs.yml. Las instrucciones para ejecutar este contenedor/script se pueden encontrar en el Repositorio Docker Oficial de Wazuh y también en el subdirectorio específico. Nota: También copia el certificado root-ca.pem en el subdirectorio graylog/, ya que lo necesitarás en un paso posterior.
Tras la compilación exitosa de la Imagen Custom Wazuh y la generación de certificados SSL, el siguiente paso es modificar todos los archivos de configuración proporcionados en el subdirectorio de cada módulo, tal como los proporcionados son plantillas tomadas de la documentación de cada herramienta; y también el archivo .env, que viene pre-rellenado hasta cierto punto para tu comodidad y se encuentra en la raíz del directorio, para adaptarse a tu Entorno y necesidades. Consulta la documentación de cada herramienta o sigue el canal de Youtube de Taylor Walton para recibir orientación sobre cómo hacerlo Configura cada herramienta.
También tendrás que seguir el paso previo al despliegue que se describe en la sección Graylog. graylog/README.md
Una vez que eso esté fuera del camino, estás listo para el Despliegue.

## Despliegue
Ahora puedes iniciar todos los contenedores de forma segura ejecutando:

```
docker compose up -d
```

### Wazuh
Tras el despliegue inicial, el Panel de Control de Wazuh mostrará un error en la comprobación de salud del índice de alertas de Wazuh, ya que aún no se ha creado. Este error solo se corregirá completamente después de integrando con éxito Graylog y el Indexador Wazuh. Puedes crear los usuarios/roles necesarios para que las próximas integraciones funcionen correctamente.

#### Wazuh Rules
Ejecuta en el contenedor de Wazuh Manager
```
docker exec -it wazuh.manager /bin/bash
```
```
dnf install git -y
```
```
curl -so ~/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/OSSIEM/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh
```

### Graylog
Mientras el contenedor está en funcionamiento, tendrás que acceder a su consola para realizar algunos pasos adicionales y añadir la CA raíz de Wazuh a la Keystore Java de Graylog. Ejecuta el siguiente comando para generar una concha dentro del contenedor.
```
docker exec -it graylog bash
```
Una vez dentro de Graylog, tendrás que copiar la Java Keystore situada en /opt/java/openjdk/lib/security/cacerts al directorio /usr/share/graylog/data/config/, para esto puedes ejecutar:
```
cp /opt/java/openjdk/lib/security/cacerts /usr/share/graylog/data/config/
```
A continuación, necesitas importar la CA raíz de Wazuh en la keystore, instalar el CD en /usr/share/graylog/data/config/ y ejecutar el siguiente comando: (cambiar el nombre del certificado y la contraseña de la keystore según sea necesario, Pero ten en cuenta que si el nombre del certificado no coincide con la plantilla, tendrás que modificar el archivo de docker-compose.yml en consecuencia)
```
cd /usr/share/graylog/data/config/
```
```
keytool -importcert -keystore cacerts -storepass changeit -alias wazuh_root_ca -file root-ca.pem
```
Se te pedirá que aceptes este certificado, escribas "sí" e introduzcas. Una vez hecho esto, Graylog podrá conectarse al indexador Wazuh.

### Velociraptor
Ahora necesitamos generar el archivo que CoPilot usará para acceder a la API de Velociraptorapi.config.yaml
```
docker exec -it velociraptor /bin/bash
```
```
./velociraptor --config server.config.yaml config api_client --name admin --role administrator,api api.config.yaml
```

### Copiloto

#### Una vez que Copilot se inicie, puedes recuperar la contraseña de administrador ejecutando el siguiente comando (solo accesible la primera vez que Copilot se inicia).

```
"$(docker ps --filter ancestor=ghcr.io/socfortress/copilot-backend:latest --format "{{.ID}}")" 2>&1 | grep "Admin user password"
```
## Post-Deployment
Cuando llegues a este punto puedes tomarte un pequeño descanso para darte una palmada en la espalda, a partir de aquí todo es cuesta abajo.
Tendrás que asegurarte de crear los usuarios necesarios en cada una de las herramientas para que las integraciones funcionen correctamente. Una vez completado eso, puedes iniciar sesión en CoPilot y empezar Aprovisionar clientes.
