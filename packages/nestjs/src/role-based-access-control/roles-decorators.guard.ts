import type { CanActivate, ExecutionContext } from '@nestjs/common'
import { Inject, Injectable, Logger, Optional } from '@nestjs/common'
import { ModuleRef, Reflector } from '@nestjs/core'
import { ROLES_KEY } from './roles.decorator.js'
import { RolesGuardOptions, ROLES_GUARD_OPTIONS, RolesGuard } from './roles.guard.js'
import { ROLES_OPTIONS_KEY } from './roles-options.decorator.js'
import { RoleBasedAccessControlService } from './role-based-access-control.service.js'
import { isObservable, lastValueFrom } from 'rxjs'
import { PUBLIC_KEY } from '../common/public.decorator.js'
import { DEFAULT_AUTH_GUARD_KEY } from '../common/default-auth-guard.decorator.js'
import type { IAuthGuard, Type } from '@nestjs/passport'
import { AuthGuard } from '@nestjs/passport'
import { ROLES_AUTH_GUARD_KEY } from './roles-auth-guard.decorator.js'
import { OptionalAuthGuard } from '../oidc-passport/index.js'

const logger = new Logger('RoleBasedAccessControl')

@Injectable()
export class RolesDecoratorsGuard implements CanActivate {
  constructor (
    @Inject(Reflector) private reflector: Reflector,
    @Inject(RoleBasedAccessControlService) private accessControlService: RoleBasedAccessControlService,
    @Optional() @Inject(ROLES_GUARD_OPTIONS) private defaultOptions: RolesGuardOptions,
    // eslint-disable-next-line unicorn/prevent-abbreviations
    @Inject(ModuleRef) private moduleRef: ModuleRef) {
  }

  async authenticate (context: ExecutionContext, effectiveOptions?: RolesGuardOptions) {
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
      logger.error('To use @Roles decorator, a auth guard must be declared at controller/handler level in @DefaultAuthGuard, @RolesAuthGuard or @RolesOptions, or globally in "defaults.authGuard" option of RoleBasedAccessControlModule.')
    }
  }

  async canActivate (context: ExecutionContext) {
    let authGuard = this.reflector.getAllAndOverride<Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]>(ROLES_AUTH_GUARD_KEY, [context.getClass(), context.getHandler()])
    if (authGuard === undefined) {
      authGuard = this.reflector.getAllAndOverride<Type<IAuthGuard> | Parameters<typeof AuthGuard>[0]>(DEFAULT_AUTH_GUARD_KEY, [context.getClass(), context.getHandler()])
    }

    const classOptions = this.reflector.get<RolesGuardOptions | undefined>(ROLES_OPTIONS_KEY, context.getClass())
    const options = this.reflector.get<RolesGuardOptions | undefined>(ROLES_OPTIONS_KEY, context.getHandler())

    let effectiveOptions: RolesGuardOptions = { ...this.defaultOptions }
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
    const roles = this.reflector.getAllAndMerge<string[]>(ROLES_KEY, [context.getClass(), context.getHandler()])

    if (public_ || roles.length === 0) {
      if (effectiveOptions.authGuard) {
        effectiveOptions.authGuard = OptionalAuthGuard(effectiveOptions.authGuard)
        await this.authenticate(context, effectiveOptions)
      }

      return true
    }

    await this.authenticate(context, effectiveOptions)

    const RolesGuardMixin = RolesGuard(roles, effectiveOptions)
    const rolesGuard = await this.moduleRef.create(RolesGuardMixin)

    const future = rolesGuard.canActivate(context)
    if (isObservable(future)) {
      return lastValueFrom(future)
    }
    return future
  }
}
