import { SetMetadata } from '@nestjs/common'

export const ROLES_KEY = '@oidc-adapters/roles'
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles)
