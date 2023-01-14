import { SetMetadata } from '@nestjs/common'

export const PUBLIC_KEY = '@oidc-adapters/public'
export const Public = (value?: boolean) => SetMetadata(PUBLIC_KEY, value ?? true)
