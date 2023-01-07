FROM quay.io/keycloak/keycloak:20.0.2 as builder
ENV KC_DB=postgres
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:20.0.2

COPY --from=builder /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
