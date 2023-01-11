import { Injectable } from '@nestjs/common'
import { AuthGuard } from '@nestjs/passport'

/**
 * An authentication guard using 'oidc' passport strategy.
 */
@Injectable()
export class OidcAuthGuard extends AuthGuard('oidc') {
}
