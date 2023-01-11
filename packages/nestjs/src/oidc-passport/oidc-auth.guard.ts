import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { mixin } from '@nestjs/common'
import type { Type } from '@nestjs/passport'
import { AuthGuard } from '@nestjs/passport'
import type { Express } from 'express'

export interface OidcAuthGuardOptions {
  type?: string | string[],
  optional?: boolean
}

/*
 * An authentication guard using 'oidc' passport strategy.
 */
export function OidcAuthGuard (options?: OidcAuthGuardOptions): Type<CanActivate> {
  class OidcAuthGuardMixin extends AuthGuard(options?.type ?? 'oidc') {
    handleRequest<T extends Express.User> (error: unknown, user: T | false, info: unknown, context: ExecutionContext, status: unknown): T | undefined {
      if (options?.optional) {
        if (!user) {
          return undefined
        }
        return user
      }
      return super.handleRequest(error, user, info, context, status)
    }
  }

  return mixin(OidcAuthGuardMixin)
}
