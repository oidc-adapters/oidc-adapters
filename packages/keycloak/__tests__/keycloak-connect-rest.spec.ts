/**
 * @group integration
 */
import { setup } from './utils/realm.js'
import { TestVector } from './utils/helper.js'

import type { AxiosError, AxiosResponse } from 'axios'
import axios from 'axios'

const realmName = 'service-node-realm'

let environment: Awaited<ReturnType<typeof setup>>

beforeAll(async () => {
  environment = await setup({ realmName, client: (app) => app.bearerOnly() })
})

afterAll(async () => {
  await environment.dispose()
})

it('Should test unprotected route.', async () => {
  const response = await axios.get(`${environment.app.address}/service/public`)
  expect(response.data.message).toEqual('public')
})

it('Should test protected route.', async () => {
  await expect(() => axios.get(`${environment.app.address}/service/admin`)).rejects.toThrow('Request failed with status code 403')
})

it('Should test for bad request on k_logout without any parameters.', async () => {
  await expect(() => axios.get(`${environment.app.address}/k_logout`)).rejects.toThrow('Request failed with status code 401')
})

it('Should test protected route with admin credentials.', async () => {
  const token = await environment.getToken()
  const response = await axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${token}` } })
  expect(response.data.message).toEqual('admin')
})

it('Should test protected route with invalid access token.', async () => {
  const token = await environment.getToken()
  const invalidToken = token!.replace(/(.+?\..+?\.).*/, '$1.Invalid')
  await expect(() => axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${invalidToken}` } })).rejects.toThrow('Request failed with status code 403')
})

it('Access should be denied for bearer client with invalid public key.', async () => {
  const environment = await setup({
    realmName,
    client: (app) => app.bearerOnly('wrongkey-app'),
    config: (config) => {
      config['realm-public-key'] = TestVector.wrongRealmPublicKey
    }
  })

  try {
    const token = await environment.getToken()

    let response: AxiosResponse | undefined
    let axiosError: AxiosError | undefined
    try {
      response = await axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${token}` } })
    } catch (error: unknown) {
      axiosError = error as AxiosError
    }

    expect(response).toBeUndefined()
    expect(axiosError?.response?.status).toEqual(403)
    expect(axiosError?.response?.data).toEqual('Access denied')
  } finally {
    await environment.dispose()
  }
})

it('Should test protected route after push revocation.', async () => {
  const environment = await setup({ realmName, client: (app) => app.bearerOnly('revokeapp') })

  try {
    const token = await environment.getToken()

    let response = await axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${token}` } })
    expect(response.data.message).toEqual('admin')
    await environment.adminClient.realms.pushRevocation({ realm: environment.realm.realm! })

    response = await axios.post(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${token}` } })
    expect(response.data).toEqual('Not found!')
  } finally {
    await environment.dispose()
  }
})

it('Should invoke admin logout.', async () => {
  const environment = await setup({ realmName, client: (app) => app.bearerOnly('anotherapp') })

  try {
    const token = await environment.getToken()

    let response = await axios.get(`${environment.app.address}/service/admin`, { headers: { Authorization: `Bearer ${token}` } })
    expect(response.data.message).toEqual('admin')
    await environment.adminClient.realms.logoutAll({ realm: environment.realm.realm! })

    response = await axios.post(`${environment.app.address}/service/admin`)
    expect(response.data).toEqual('Not found!')
  } finally {
    await environment.dispose()
  }
})
