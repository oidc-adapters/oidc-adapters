import { SetMetadata } from '@nestjs/common'

export const SCOPES_KEY = '@oidc-adapters/scopes'
export const Scopes = (...scopes: string[]) => SetMetadata(SCOPES_KEY, scopes)
