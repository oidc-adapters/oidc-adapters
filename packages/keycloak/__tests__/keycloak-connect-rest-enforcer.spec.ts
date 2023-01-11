/**
 * @group integration
 */
import { setup } from './utils/realm.js'
import type { AxiosError, AxiosResponse } from 'axios'
import axios from 'axios'

let environment: Awaited<ReturnType<typeof setup>>

beforeAll(async () => {
  environment = await setup({ realmName: 'policy-enforcer-realm', client: (app) => app.enforcerResourceServer() })
})

afterAll(async () => {
  await environment.dispose()
})

it('Should test access to protected resource and scope view.', async () => {
  const token = await environment.getToken()

  const response = await axios.get(`${environment.app.address}/protected/enforcer/resource`, { headers: { Authorization: `Bearer ${token}` } })
  expect(response.data.message).toEqual('resource:view')
  expect(response.data.permissions.length).toEqual(1)
  expect(response.data.permissions[0].rsname).toEqual('resource')
  expect(response.data.permissions[0].scopes[0]).toEqual('view')
})

it('Should test access to protected resource and scope view without authorization header.', async () => {
  await expect(() => axios.get(`${environment.app.address}/protected/enforcer/resource`)).rejects.toThrow('Request failed with status code 403')
})

it('Should test access to protected resource and scope update - and returned permissions.', async () => {
  const token = await environment.getToken()
  const response = await axios.post(`${environment.app.address}/protected/enforcer/resource`, undefined, {
    headers: { authorization: `Bearer ${token}` }
  })
  expect(response.data.message).toEqual('resource:update')
  expect(response.data.permissions).toHaveLength(1)
  expect(response.data.permissions[0].rsname).toEqual('resource')
  expect(response.data.permissions[0].scopes[0]).toEqual('update')
})

it('Should test no access to protected resource and scope delete.', async () => {
  const token = await environment.getToken()

  await expect(() => axios.delete(`${environment.app.address}/protected/enforcer/resource`, { headers: { Authorization: `Bearer ${token}` } })).rejects.toThrow('Request failed with status code 403')
})

it('Should test no access to protected resource and scope view and delete.', async () => {
  const token = await environment.getToken()

  let response: AxiosResponse | undefined
  let axiosError: AxiosError | undefined
  try {
    response = await axios.get(`${environment.app.address}/protected/enforcer/resource-view-delete`, { headers: { Authorization: `Bearer ${token}` } })
  } catch (error: unknown) {
    axiosError = error as AxiosError
  }

  expect(response).toBeUndefined()
  expect(axiosError?.response?.status).toEqual(403)
  expect((axiosError?.response?.data as { permissions: unknown }).permissions).toBeUndefined()
  expect(axiosError?.response?.data).toEqual('Access denied')
})

it('Should test access to protected resource pushing claims.', async () => {
  const token = await environment.getToken()

  const response = await axios.get(`${environment.app.address}/protected/enforcer/resource-claims?user_agent=mozilla`, { headers: { Authorization: `Bearer ${token}` } })

  expect(response.data.message).toEqual('mozilla')
  expect(response.data.permissions[0].rsname).toEqual('photo')
  expect(response.data.permissions[0].claims.user_agent).toHaveLength(1)
  expect(response.data.permissions[0].claims.user_agent[0]).toEqual('mozilla')
})

it('Should test no access to protected resource wrong claims.', async () => {
  const token = await environment.getToken()

  let response: AxiosResponse | undefined
  let axiosError: AxiosError | undefined
  try {
    response = await axios.get(`${environment.app.address}/protected/enforcer/resource-claims?user_agent=ie`, { headers: { Authorization: `Bearer ${token}` } })
  } catch (error: unknown) {
    axiosError = error as AxiosError
  }

  expect(response).toBeUndefined()
  expect(axiosError?.response?.status).toEqual(403)
  expect((axiosError?.response?.data as { permissions: unknown }).permissions).toBeUndefined()
  expect(axiosError?.response?.data).toEqual('Access denied')
})

it('Should test access to resources without any permission defined.', async () => {
  const token = await environment.getToken()
  const response = await axios.get(`${environment.app.address}/protected/enforcer/no-permission-defined`, { headers: { Authorization: `Bearer ${token}` } })

  expect(response.data.message).toEqual('always grant')
  expect(response.data.permissions).toBeUndefined()
})
