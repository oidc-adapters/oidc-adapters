import { SetMetadata } from '@nestjs/common'
import type { AuthGuard, IAuthGuard, Type } from '@nestjs/passport'

export const ROLES_AUTH_GUARD_KEY = '@oidc-adapters/roles-auth-guard'
export const RolesAuthGuard = (value?: Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]) => SetMetadata(ROLES_AUTH_GUARD_KEY, value)
