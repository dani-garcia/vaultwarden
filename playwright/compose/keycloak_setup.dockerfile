FROM quay.io/keycloak/keycloak:25.0.1

COPY keycloak_setup.sh /keycloak_setup.sh

entrypoint [ "bash", "-c", "/keycloak_setup.sh"]
