/**
 * @group integration
 */
import { setup } from './utils/realm.js'
import { TestVector } from './utils/helper.js'

import type { AxiosError, AxiosResponse } from 'axios'
import axios from 'axios'
import type Grant from '../src/middleware/auth-utils/grant.js'

const auth = {
  username: 'test-admin',
  password: 'password'
}

const getSessionCookie = (response: AxiosResponse) => {
  const setCookie = response.headers['set-cookie']
  if (!setCookie) return
  return setCookie[0]
}

let environment: Awaited<ReturnType<typeof setup>>

beforeAll(async () => {
  environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential() })
})

afterAll(async () => {
  await environment.dispose()
})

it('Should test protected route.', async () => {
  await expect(() => axios.get(`${environment.app.address}/service/admin`)).rejects.toThrow('Request failed with status code 403')
})

it('Should test protected route with admin credentials.', async () => {
  const token = await environment.getToken()
  const response = await axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${token}` } })
  expect(response.data.message).toEqual('admin')
})

it('Should test protected route with invalid access token.', async () => {
  const token = await environment.getToken()
  const invalidToken = token!.replace(/(.+?\..+?\.).*/, '$1.Invalid')

  let response: AxiosResponse | undefined
  let axiosError: AxiosError | undefined
  try {
    response = await axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${invalidToken}` } })
  } catch (error: unknown) {
    axiosError = error as AxiosError
  }

  expect(response).toBeUndefined()
  expect((axiosError?.response?.data as { permissions: unknown }).permissions).toBeUndefined()
  expect(axiosError?.response?.data).toEqual('Access denied')
})

it('Should handle direct access grants.', async () => {
  const response = await axios.post(`${environment.app.address}/service/grant`, auth)
  expect(response.data.id_token).toBeDefined()
  expect(response.data.access_token).toBeDefined()
  expect(response.data.refresh_token).toBeDefined()
})

it('Should store the grant.', async () => {
  const postResponse = await axios.post(`${environment.app.address}/service/grant`, auth)
  const sessionCookie = getSessionCookie(postResponse)
  if (!sessionCookie) throw new Error('missing cookie')
  const response = await axios.get(`${environment.app.address}/service/grant`, { headers: { Cookie: sessionCookie } })
  expect(response.data.id_token).toBeDefined()
  expect(response.data.access_token).toBeDefined()
  expect(response.data.refresh_token).toBeDefined()
})

it('Should not store grant on bearer request', async () => {
  const grantResponse = await axios.post<Grant>(`${environment.app.address}/service/grant`, auth)

  const grant = grantResponse.data
  const sessionCookie = getSessionCookie(grantResponse)

  if (!sessionCookie) throw new Error('missing cookie')
  const securedResponse = await axios.get<{ message?: string }>(`${environment.app.address}/service/secured`, {
    headers: {
      Authorization: `Bearer ${grant.access_token?.token}`,
      Cookie: sessionCookie
    }
  })

  expect(securedResponse.data.message).toEqual('secured')
  const grantResponse2 = await axios.get(`${environment.app.address}/service/grant`, {
    headers: {
      Cookie: sessionCookie
    }
  })

  expect(grantResponse2.data.id_token).toBeDefined()
  expect(grantResponse2.data.access_token).toBeDefined()
  expect(grantResponse2.data.refresh_token).toBeDefined()
})

it('Should test admin logout endpoint with incomplete payload', async () => {
  const environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential('adminapp') })
  try {
    let response: AxiosResponse | undefined
    let axiosError: AxiosError | undefined
    try {
      response = await axios.post(`${environment.app.address}/k_logout`, TestVector.logoutIncompletePayload)
    } catch (error: unknown) {
      axiosError = error as AxiosError
    }

    expect(response).toBeUndefined()
    expect(axiosError?.response?.status).toEqual(401)
    expect(axiosError?.response?.data).toEqual('failed to load public key to verify token. Reason: kid is missing')
  } finally {
    await environment.dispose()
  }
})

it('Should test admin logout endpoint with payload signed by a different key pair', async () => {
  const environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential('adminapp2') })
  try {
    let response: AxiosResponse | undefined
    let axiosError: AxiosError | undefined
    try {
      response = await axios.post(`${environment.app.address}/k_logout`, TestVector.logoutWrongKeyPairPayload)
    } catch (error: unknown) {
      axiosError = error as AxiosError
    }

    expect(response).toBeUndefined()
    expect(axiosError?.response?.status).toEqual(401)
    expect(axiosError?.response?.data).toEqual('admin request failed: invalid token (signature)')
  } finally {
    await environment.dispose()
  }
})

it('Should test admin logout endpoint with valid payload', async () => {
  const environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential('adminapp3') })
  try {
    const response = await axios.post(`${environment.app.address}/k_logout`, TestVector.logoutValidPayload)
    expect(response.status).toBe(200)
  } finally {
    environment.app.destroy()
  }
})

it('Should test admin push_not_before endpoint with incomplete payload', async () => {
  const environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential('adminapp5') })
  try {
    let response: AxiosResponse | undefined
    let axiosError: AxiosError | undefined
    try {
      response = await axios.post(`${environment.app.address}/k_push_not_before`, TestVector.notBeforeIncompletePayload)
    } catch (error: unknown) {
      axiosError = error as AxiosError
    }

    expect(response).toBeUndefined()
    expect(axiosError?.response?.status).toEqual(401)
    expect(axiosError?.response?.data).toEqual('failed to load public key to verify token. Reason: kid is missing')
  } finally {
    await environment.dispose()
  }
})

it('Should test admin push_not_before endpoint with payload signed by a different key pair', async () => {
  const environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential('adminapp6') })
  try {
    let response: AxiosResponse | undefined
    let axiosError: AxiosError | undefined
    try {
      response = await axios.post(`${environment.app.address}/k_push_not_before`, TestVector.notBeforeWrongKeyPairPayload)
    } catch (error: unknown) {
      axiosError = error as AxiosError
    }

    expect(response).toBeUndefined()
    expect(axiosError?.response?.status).toEqual(401)
    expect(axiosError?.response?.data).toEqual('admin request failed: invalid token (signature)')
  } finally {
    await environment.dispose()
  }
})

it('Should verify during authentication if the token contains the client name as audience.', async () => {
  const environment = await setup({
    realmName: 'mixed-mode-realm',
    client: (app) => app.confidential('audience-app'),
    config: (config) => { config.verifyTokenAudience = true }
  })

  try {
    const response = await axios.post(`${environment.app.address}/service/grant`, auth)

    expect(response.data.id_token).toBeDefined()
    expect(response.data.access_token).toBeDefined()
    expect(response.data.refresh_token).toBeDefined()
  } finally {
    await environment.dispose()
  }
})

it('Should test admin push_not_before endpoint with valid payload', async () => {
  const environment = await setup({ realmName: 'mixed-mode-realm', client: (app) => app.confidential('adminapp7') })

  try {
    const response = await axios.post(`${environment.app.address}/k_push_not_before`, TestVector.notBeforeValidPayload)

    expect(response.status).toEqual(200)
  } finally {
    await environment.dispose()
  }
})

// eslint-disable-next-line jest/no-disabled-tests
it.skip('Should logout with redirect url', async () => {
  // Test disabled as it is not supported since Keycloak v18
  // See https://www.keycloak.org/2022/04/keycloak-1800-released#_openid_connect_logout
  const serviceEndpoint = `${environment.app.address}/service/grant`
  const logoutEndpoint = `${environment.app.address}/logout?redirect_url=http%3A%2F%2Flocalhost%3A${environment.app.port}%2Fbye`
  let response = await axios.post(serviceEndpoint, auth)
  const sessionCookie = getSessionCookie(response)
  if (!sessionCookie) {
    throw new Error('Session cookie is not defined')
  }
  response = await axios.get(logoutEndpoint, { headers: { Cookie: sessionCookie } })
  expect(response.request.path).toEqual('/bye')
})
