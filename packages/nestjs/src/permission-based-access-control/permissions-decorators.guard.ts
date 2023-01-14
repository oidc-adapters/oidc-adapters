import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import { ModuleRef, Reflector } from '@nestjs/core'
import { isObservable, lastValueFrom } from 'rxjs'
import { PermissionBasedAccessControlService } from './permission-based-access-control.service.js'
import { RESOURCE_KEY } from './resource.decorator.js'
import { SCOPES_KEY } from './scopes.decorator.js'
import { PERMISSIONS_OPTIONS_KEY } from './permissions-options.decorator.js'
import { PermissionsGuardOptions, PERMISSIONS_GUARD_OPTIONS, PermissionsGuard } from './permissions.guard.js'
import { PUBLIC_KEY } from '../common/public.decorator.js'
import type { IAuthGuard, Type } from '@nestjs/passport'
import { AuthGuard } from '@nestjs/passport'
import { DEFAULT_AUTH_GUARD_KEY } from '../common/default-auth-guard.decorator.js'
import { OptionalAuthGuard } from '../oidc-passport/index.js'
import { PERMISSIONS_AUTH_GUARD_KEY } from './permissions-auth-guard.decorator.js'

const logger = new Logger('PermissionsBasedAccessControl')

@Injectable()
export class PermissionsDecoratorsGuard implements CanActivate {
  constructor (
    @Inject(Reflector) private reflector: Reflector,
    @Inject(PermissionBasedAccessControlService) private accessControlService: PermissionBasedAccessControlService,
    @Optional() @Inject(PERMISSIONS_GUARD_OPTIONS) private defaultOptions: PermissionsGuardOptions,
    // eslint-disable-next-line unicorn/prevent-abbreviations
    @Inject(ModuleRef) private moduleRef: ModuleRef) {
  }

  async authenticate (context: ExecutionContext, effectiveOptions?: PermissionsGuardOptions) {
    let authGuardOption = effectiveOptions?.authGuard

    if (authGuardOption !== undefined) {
      if (typeof authGuardOption === 'string' || Array.isArray(authGuardOption)) {
        authGuardOption = AuthGuard(authGuardOption)
      }
      const authGuard = await this.moduleRef.create(authGuardOption)

      const auth = await authGuard.canActivate(context)
      if (!auth) {
        return false
      }
    } else {
      logger.error('To use @Resource and @Scopes decorators, a auth guard must be declared at controller/handler level in @DefaultAuthGuard, @PermissionsAuthGuard or @PermissionsOptions, or globally in "defaults.authGuard" option of PermissionBasedAccessControlModule.')
    }
  }

  async canActivate (context: ExecutionContext) {
    let authGuard = this.reflector.getAllAndOverride<Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]>(PERMISSIONS_AUTH_GUARD_KEY, [context.getClass(), context.getHandler()])
    if (authGuard === undefined) {
      authGuard = this.reflector.getAllAndOverride<Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]>(DEFAULT_AUTH_GUARD_KEY, [context.getClass(), context.getHandler()])
    }

    const classOptions = this.reflector.get<PermissionsGuardOptions | undefined>(PERMISSIONS_OPTIONS_KEY, context.getClass())
    const options = this.reflector.get<PermissionsGuardOptions | undefined>(PERMISSIONS_OPTIONS_KEY, context.getHandler())

    let effectiveOptions: PermissionsGuardOptions = { ...this.defaultOptions }
    if (authGuard !== undefined) {
      effectiveOptions.authGuard = authGuard
    }

    if (classOptions !== undefined) {
      effectiveOptions = { ...effectiveOptions, ...classOptions }
    }
    if (options !== undefined) {
      effectiveOptions = { ...effectiveOptions, ...options }
    }

    const public_ = this.reflector.getAllAndOverride<boolean | undefined>(PUBLIC_KEY, [context.getClass(), context.getHandler()])
    const resource = this.reflector.getAllAndOverride<string | undefined>(RESOURCE_KEY, [context.getClass(), context.getHandler()])
    const scopes = this.reflector.getAllAndMerge<string[]>(SCOPES_KEY, [context.getClass(), context.getHandler()])

    if (public_ || (resource === undefined && scopes.length === 0)) {
      if (effectiveOptions.authGuard) {
        effectiveOptions.authGuard = OptionalAuthGuard(effectiveOptions.authGuard)
        await this.authenticate(context, effectiveOptions)
      }

      return true
    }

    await this.authenticate(context, effectiveOptions)

    const PermissionsGuardMixin = PermissionsGuard({ resource, scopes }, effectiveOptions)
    const permissionsGuard = await this.moduleRef.create(PermissionsGuardMixin)

    const future = permissionsGuard.canActivate(context)
    if (isObservable(future)) {
      return lastValueFrom(future)
    }
    return future
  }
}
