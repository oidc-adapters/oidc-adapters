import type { PermissionsGuardOptions } from '../permission-based-access-control/permissions.guard.js'
import { SetMetadata } from '@nestjs/common'

export const PERMISSIONS_OPTIONS_KEY = '@oidc-adapters/permissions-options'
export const PermissionsOptions = (options: PermissionsGuardOptions) => SetMetadata(PERMISSIONS_OPTIONS_KEY, options)
