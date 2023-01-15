import { Test } from '@nestjs/testing'
import type { INestApplication } from '@nestjs/common'
import { Controller, Get, Request, UseGuards } from '@nestjs/common'
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import type * as Express from 'express'
import { agent } from 'supertest'
import { RoleBasedAccessControlModule } from './role-based-access-control.module.js'
import type { KeycloakTokenClaims } from '@oidc-adapters/keycloak'
import { KeycloakRolesProvider } from '@oidc-adapters/keycloak'
import { OidcPassportModule, OptionalAuthGuard } from '../oidc-passport/index.js'
import { RolesGuard } from './roles.guard.js'
import { directGrant } from '../../__tests__/utils/auth.js'
import { Roles } from './roles.decorator.js'
import { Public } from '../common/public.decorator.js'
import { AuthGuard } from '@nestjs/passport'
import { RolesOptions } from './roles-options.decorator.js'

interface TestResponse {
  user: typeof Express.request.user
}

describe('RoleBasedAccessControlModule (guards)', () => {
  let app: INestApplication

  @Controller()
  class TestController {
    @Get('/public')
    @UseGuards(OptionalAuthGuard('oidc'))
    getPublic (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/admin')
    @UseGuards(AuthGuard('oidc'), RolesGuard('admin'))
    getAdmin (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/realm-admin')
    @UseGuards(AuthGuard('oidc'), RolesGuard('realm:realm-admin'))
    getRealmAdmin (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }
  }

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/keycloak-test'] } }),
        RoleBasedAccessControlModule.forRoot({
          providerType: 'user',
          provider: (user) => new KeycloakRolesProvider(user.jwtPayload as KeycloakTokenClaims)
        })
      ],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('RoleBasedAccessControlModule', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse
      expect(testBody.user).toBeUndefined()
    })

    it('should access public endpoint with authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse
      expect(testBody.user).toBeDefined()
    })

    it('should not access admin endpoint without authentication', async () => {
      await agent(app.getHttpServer())
        .get('/admin')
        .expect(401)
    })

    it('should access admin endpoint with authentication', async () => {
      await agent(app.getHttpServer())
        .get('/admin')
        .use(await directGrant('admin', 'admin'))
        .expect(200)
    })

    it('should not access admin endpoint with authentication but invalid role', async () => {
      await agent(app.getHttpServer())
        .get('/admin')
        .use(await directGrant('user', 'user'))
        .expect(403)
    })

    it('should access realm admin endpoint with authentication', async () => {
      await agent(app.getHttpServer())
        .get('/realm-admin')
        .use(await directGrant('admin', 'admin'))
        .expect(200)
    })

    it('should not access realm admin endpoint with authentication but missing role', async () => {
      await agent(app.getHttpServer())
        .get('/realm-admin')
        .use(await directGrant('user', 'user'))
        .expect(403)
    })
  })
})

describe('RoleBasedAccessControlModule (decorators on handlers)', () => {
  let app: INestApplication

  @Controller()
  @RolesOptions({ authGuard: 'oidc' })
  class TestController {
    @Get('/public')
    getPublic (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/admin')
    @Roles('admin')
    getAdmin (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/realm-admin')
    @Roles('realm:realm-admin')
    getRealmAdmin (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }
  }

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/keycloak-test'] } }),
        RoleBasedAccessControlModule.forRoot({
          providerType: 'user',
          provider: (user) => new KeycloakRolesProvider(user.jwtPayload as KeycloakTokenClaims)
        })
      ],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  it('should access public endpoint without authentication', async () => {
    const response = await agent(app.getHttpServer())
      .get('/public')
      .expect(200)

    const testBody = response.body as TestResponse
    expect(testBody.user).toBeUndefined()
  })

  it('should not access admin endpoint without authentication', async () => {
    await agent(app.getHttpServer())
      .get('/admin')
      .expect(401)
  })

  it('should access admin endpoint with authentication', async () => {
    await agent(app.getHttpServer())
      .get('/admin')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should not access admin endpoint with authentication but invalid role', async () => {
    await agent(app.getHttpServer())
      .get('/admin')
      .use(await directGrant('user', 'user'))
      .expect(403)
  })

  it('should access realm admin endpoint with authentication', async () => {
    await agent(app.getHttpServer())
      .get('/realm-admin')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should not access realm admin endpoint with authentication but missing role', async () => {
    await agent(app.getHttpServer())
      .get('/realm-admin')
      .use(await directGrant('user', 'user'))
      .expect(403)
  })
})

describe('RoleBasedAccessControlModule (decorators on class and handlers)', () => {
  let app: INestApplication

  @Controller()
  @Roles('admin')
  class TestController {
    @Get('/public')
    @Public()
    getPublic (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/admin')
    getAdmin (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }

    @Get('/realm-admin')
    @Roles('realm:realm-admin')
    getRealmAdmin (@Request() request: Express.Request) {
      return {
        user: request.user
      }
    }
  }

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/keycloak-test'] } }),
        RoleBasedAccessControlModule.forRoot({
          providerType: 'user',
          provider: (user) => new KeycloakRolesProvider(user.jwtPayload as KeycloakTokenClaims),
          defaults: {
            authGuard: AuthGuard('oidc')
          }
        })
      ],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  it('should access public endpoint without authentication', async () => {
    const response = await agent(app.getHttpServer())
      .get('/public')
      .expect(200)

    const testBody = response.body as TestResponse
    expect(testBody.user).toBeUndefined()
  })

  it('should access public endpoint with authentication', async () => {
    const response = await agent(app.getHttpServer())
      .get('/public')
      .use(await directGrant('admin', 'admin'))
      .expect(200)

    const testBody = response.body as TestResponse
    expect(testBody.user).toBeDefined()
  })

  it('should not access admin endpoint without authentication', async () => {
    await agent(app.getHttpServer())
      .get('/admin')
      .expect(401)
  })

  it('should access admin endpoint with authentication', async () => {
    await agent(app.getHttpServer())
      .get('/admin')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should not access admin endpoint with authentication but invalid role', async () => {
    await agent(app.getHttpServer())
      .get('/admin')
      .use(await directGrant('user', 'user'))
      .expect(403)
  })

  it('should access realm admin endpoint with authentication', async () => {
    await agent(app.getHttpServer())
      .get('/realm-admin')
      .use(await directGrant('admin', 'admin'))
      .expect(200)
  })

  it('should not access realm admin endpoint with authentication but missing role', async () => {
    await agent(app.getHttpServer())
      .get('/realm-admin')
      .use(await directGrant('user', 'user'))
      .expect(403)
  })
})
