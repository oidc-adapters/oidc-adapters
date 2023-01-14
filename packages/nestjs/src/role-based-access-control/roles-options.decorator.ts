import { SetMetadata } from '@nestjs/common'
import type { RolesGuardOptions } from './roles.guard.js'

export const ROLES_OPTIONS_KEY = '@oidc-adapters/roles-options'
export const RolesOptions = (options: RolesGuardOptions) => SetMetadata(ROLES_OPTIONS_KEY, options)
