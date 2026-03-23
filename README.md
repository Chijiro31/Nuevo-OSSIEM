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
