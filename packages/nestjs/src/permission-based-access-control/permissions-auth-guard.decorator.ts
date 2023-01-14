import { SetMetadata } from '@nestjs/common'
import type { AuthGuard, IAuthGuard, Type } from '@nestjs/passport'

export const PERMISSIONS_AUTH_GUARD_KEY = '@oidc-adapters/permissions-auth-guard'
export const PermissionsAuthGuard = (value?: Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]) => SetMetadata(PERMISSIONS_AUTH_GUARD_KEY, value)
