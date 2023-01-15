import { Test } from '@nestjs/testing'
import type { OidcPassportOptions, OidcPassportOptionsFactory } from './oidc-passport.module.js'
import { OidcPassportModule } from './oidc-passport.module.js'
import type { INestApplication } from '@nestjs/common'
import { Controller, Get, Module, Request, UseGuards } from '@nestjs/common'
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import type * as Express from 'express'
import { agent } from 'supertest'
import { directGrant } from '../../__tests__/utils/auth.js'
import { AuthGuard } from '@nestjs/passport'
import { OptionalAuthGuard } from './optional-auth.guard.js'

interface TestResponse {
  public: boolean,
  user: typeof Express.request.user
}

@Controller()
class TestController {
  @Get('/public')
  getPublic (@Request() request: Express.Request) {
    return {
      public: true,
      user: request.user
    }
  }

  @Get('/optional')
  @UseGuards(OptionalAuthGuard(AuthGuard('oidc')))
  getOptional (@Request() request: Express.Request) {
    return {
      public: true,
      user: request.user
    }
  }

  @Get('/custom')
  @UseGuards(AuthGuard('oidc-custom'))
  getCustom (@Request() request: Express.Request) {
    return {
      public: true,
      user: request.user
    }
  }

  @Get('/private')
  @UseGuards(AuthGuard('oidc'))
  getPrivate (@Request() request: Express.Request) {
    return {
      public: false,
      user: request.user
    }
  }
}

describe('OidcPassportModule (default)', () => {
  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRoot({ options: { allowedIssuers: ['http://localhost:8109/realms/keycloak-test'] } })
      ],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should access public endpoint with authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should access optional endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/optional')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should access optional endpoint with authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/optional')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeDefined()
    })

    it('should not access private endpoint without authentication', async () => {
      return agent(app.getHttpServer())
        .get('/private')
        .expect(401)
    })

    it('should access private endpoint with valid bearer token and return user', async () => {
      const response = await agent(app.getHttpServer())
        .get('/private')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeFalsy()
      expect(testBody.user?.jwtPayload).toBeDefined()
    })
  })
})

describe('OidcPassportModule (custom name)', () => {
  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRoot({
        options: { allowedIssuers: ['http://localhost:8109/realms/master'] },
        strategyName: 'oidc-custom'
      })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should not access private endpoint without authentication', async () => {
      return agent(app.getHttpServer())
        .get('/private')
        .expect(401)
    })
  })
})

describe('OidcPassportModule (app guard true)', () => {
  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRoot({
        options: { allowedIssuers: ['http://localhost:8109/realms/master'] },
        strategyName: 'oidc-custom',
        appGuard: true
      })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should not access public endpoint without authentication', async () => {
      await agent(app.getHttpServer())
        .get('/public')
        .expect(401)
    })
  })
})

describe('OidcPassportModule (app guard optional)', () => {
  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRoot({
        options: { allowedIssuers: ['http://localhost:8109/realms/master'] },
        strategyName: 'oidc-custom',
        appGuard: 'optional'
      })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })
  })
})

describe('OidcPassportModule (forRootAsync useFactory)', () => {
  let app: INestApplication

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRootAsync({
        inject: ['allowedIssuers'],
        useFactory: (allowedIssuers: string[]) => {
          return {
            options: {
              allowedIssuers
            }
          }
        },
        extraProviders: [{
          provide: 'allowedIssuers',
          useValue: ['http://localhost:8109/realms/keycloak-test']
        }]
      })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should access private endpoint with valid bearer token and return user', async () => {
      const response = await agent(app.getHttpServer())
        .get('/private')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeFalsy()
      expect(testBody.user?.jwtPayload).toBeDefined()
    })
  })
})

describe('OidcPassportModule (forRootAsync useClass)', () => {
  let app: INestApplication

  class MyOptionsFactory implements OidcPassportOptionsFactory {
    createOidcPassportOptions (): Promise<OidcPassportOptions> | OidcPassportOptions {
      return {
        options: {
          allowedIssuers: ['http://localhost:8109/realms/keycloak-test']
        }
      }
    }
  }

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [OidcPassportModule.forRootAsync({
        useClass: MyOptionsFactory
      })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should access private endpoint with valid bearer token and return user', async () => {
      const response = await agent(app.getHttpServer())
        .get('/private')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeFalsy()
      expect(testBody.user?.jwtPayload).toBeDefined()
    })
  })
})

describe('OidcPassportModule (forRootAsync useExisting)', () => {
  let app: INestApplication

  class MyOptionsFactory implements OidcPassportOptionsFactory {
    createOidcPassportOptions (): Promise<OidcPassportOptions> | OidcPassportOptions {
      return {
        options: {
          allowedIssuers: ['http://localhost:8109/realms/keycloak-test']
        }
      }
    }
  }

  @Module({
    providers: [MyOptionsFactory],
    exports: [MyOptionsFactory]
  })
  class OptionsModule {}

  beforeEach(async () => {
    const testingModule = await Test.createTestingModule({
      imports: [
        OidcPassportModule.forRootAsync({
          imports: [OptionsModule],
          useExisting: MyOptionsFactory
        })],
      controllers: [TestController]
    }).compile()

    app = testingModule.createNestApplication()
    await app.init()
  })

  afterEach(async () => {
    await app.close()
  })

  describe('OidcPassportStrategy', () => {
    it('should access public endpoint without authentication', async () => {
      const response = await agent(app.getHttpServer())
        .get('/public')
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeTruthy()
      expect(testBody.user).toBeUndefined()
    })

    it('should access private endpoint with valid bearer token and return user', async () => {
      const response = await agent(app.getHttpServer())
        .get('/private')
        .use(await directGrant('admin', 'admin'))
        .expect(200)

      const testBody = response.body as TestResponse

      expect(testBody.public).toBeFalsy()
      expect(testBody.user?.jwtPayload).toBeDefined()
    })
  })
})
