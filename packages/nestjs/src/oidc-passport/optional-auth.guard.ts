import type { ExecutionContext } from '@nestjs/common'
import { Injectable, mixin } from '@nestjs/common'
import type { IAuthGuard, Type } from '@nestjs/passport'
import { AuthGuard } from '@nestjs/passport'

/*
 * An authentication guard wrapper to make another authentication guard optional.
 */
export function OptionalAuthGuard (AuthGuardType: Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]): Type<IAuthGuard> {
  if (typeof AuthGuardType === 'string' || Array.isArray(AuthGuardType) || AuthGuardType === undefined) {
    AuthGuardType = AuthGuard(AuthGuardType)
  }

  @Injectable()
  class OptionalAuthGardMixin extends AuthGuardType {
    // eslint-disable-next-line n/handle-callback-err
    handleRequest<T> (error: unknown, user: T | false, info: unknown, context: ExecutionContext, status: unknown): T | undefined {
      if (user === false) {
        return undefined
      }

      try {
        return super.handleRequest(error, user, info, context, status)
      } catch {
        return undefined
      }
    }
  }

  return mixin(OptionalAuthGardMixin)
}
