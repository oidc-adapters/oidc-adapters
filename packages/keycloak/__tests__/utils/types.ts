import type KeycloakAdminClient from '@keycloak/keycloak-admin-client'

export type RealmRepresentation = NonNullable<Awaited<ReturnType<KeycloakAdminClient['realms']['findOne']>>>
