import { SetMetadata } from '@nestjs/common'
import type { AuthGuard, IAuthGuard, Type } from '@nestjs/passport'

export const DEFAULT_AUTH_GUARD_KEY = '@oidc-adapters/default-auth-guard'
export const DefaultAuthGuard = (value?: Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]) => SetMetadata(DEFAULT_AUTH_GUARD_KEY, value)
