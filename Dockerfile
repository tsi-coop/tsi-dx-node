# Use an official Jetty base image with Java 17
FROM jetty:jdk17

# Set timezone non-interactively
ENV TZ=Asia/Kolkata

# Set environment variables for Jetty/Application (optional, but good practice)
ENV JETTY_BASE /var/lib/jetty
ENV JETTY_HOME /usr/local/jetty
ENV JETTY_RUN /tmp/jetty

RUN java -jar "$JETTY_HOME/start.jar" --add-modules=http,ssl,https,jdbc,jndi,ee10-deploy

# Generate a dev self-signed keystore for the HTTPS/P2P connector on port 8443.
# Partners.java always uses https:// (see normalizeUrl), so Jetty must serve TLS.
# This cert is transport-only; mTLS identity validation is done at the app layer.
RUN mkdir -p ${JETTY_BASE}/etc && keytool -genkeypair -alias jetty \
    -keyalg RSA -keysize 2048 \
    -keystore ${JETTY_BASE}/etc/keystore.p12 \
    -storetype PKCS12 \
    -storepass dev-p2p-tsi \
    -keypass dev-p2p-tsi \
    -validity 3650 \
    -dname "CN=tsi-dx-node,O=TSI,C=US" \
    -ext "SAN=dns:node-a-server-1,dns:node-b-server-1,dns:localhost,ip:127.0.0.1" \
    -noprompt

# Expose keystore password as an env var so Partners.java can load the transport cert
ENV P2P_KEYSTORE_PASS=dev-p2p-tsi

# Point the SSL module at the dev keystore on port 8443
RUN { \
    echo 'jetty.ssl.port=8443'; \
    echo 'jetty.sslContext.keyStorePath=etc/keystore.p12'; \
    echo 'jetty.sslContext.keyStoreType=PKCS12'; \
    echo 'jetty.sslContext.keyStorePassword=dev-p2p-tsi'; \
    echo 'jetty.sslContext.keyManagerPassword=dev-p2p-tsi'; \
    } >> ${JETTY_BASE}/start.d/ssl.ini

# Switch to the 'jetty' user
USER jetty

# Copy your WAR file into Jetty's webapps directory
COPY target/tsi_dx_node.war ${JETTY_BASE}/webapps/root.war

# Expose HTTP (browser UI) and HTTPS (P2P mTLS)
EXPOSE 8080
EXPOSE 8443

# The default CMD of the Jetty base image is usually sufficient to start Jetty.
# CMD ["java", "-jar", "$JETTY_HOME/start.jar"] # This is often the default or similar