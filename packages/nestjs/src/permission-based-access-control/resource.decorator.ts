import { SetMetadata } from '@nestjs/common'

export const RESOURCE_KEY = '@oidc-adapters/resource'
export const Resource = (resource: string) => SetMetadata(RESOURCE_KEY, resource)
