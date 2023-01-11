/**
 * A helper for test cases and fixtures
 */
import type { PathOrFileDescriptor } from 'node:fs'
import { readFileSync } from 'node:fs'
import type { RealmRepresentation } from './types.js'
import type { ConfigInput } from '../../src/middleware/auth-utils/config.js'

/**
 * Utility to parse realm templates
 * @param {PathOrFileDescriptor} file - Realm template JSON file
 * @param {string} realmName - Realm name
 */

export function parse (file: PathOrFileDescriptor, realmName: string): RealmRepresentation {
  const content = readFileSync(file, 'utf8')
    .replace(/{{realm}}/g, realmName)
  return JSON.parse(content) as RealmRepresentation
}

/**
 * Utility to parse realm templates
 * @param {PathOrFileDescriptor} file - Realm template JSON file
 * @param {string} port - The HTTP port which the client app will listen. This is necessary
 * to provide the proper redirect URIs
 * @param {object} name - Host name which the client app will listen.
 */

export function parseClient (file: PathOrFileDescriptor, port: string | undefined, name: string): ConfigInput {
  const content = readFileSync(file, 'utf8')
    .replace(/{{name}}/g, name)
    .replace(/{{port}}/g, port ?? '3000')

  return JSON.parse(content) as ConfigInput
}

/**
 * Utility to provide testing vectors instead of
 * a bunch of duplicate files with small changes
 */
export const TestVector = {
  wrongRealmPublicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAikGBvYGniAJ59ZjpaSDw2o+j40Ila/dWfN8qA1dzXJesH9Z1sZrcevJB+rfxoZDaWMz2l9Q3OxG/qolTpsQl8NBdb5tymic9qDkAIsiyKThzjcfs5lOSxfnkHn6+Z0QbrYnXQs/cGvQ1Ai81M1M1O6BHDWu05n8c977h+BsfLmqGj7MZZj9gw9RM84RIKDGHTbFh9YyXBJVtqbOhRD7hcB0O9olDZb7mQ5A8gsMctcUhsVBy3xKCLMD41XU92rQ9FAlsV9mBglLqaVWr2mxQItN3lgjE02L8UyorI3T0uprIsnv7B2NwUC5ZhwZGfnBznUPVrT6makEJklpg5if3qQIDAQAB',
  logoutValidPayload: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkZKODZHY0YzalRiTkxPY280TnZaa1VDSVVtZllDcW9xdE9RZU1mYmhObEUifQ.eyJpYXQiOjE1NTY2MTcwNzksInJlc291cmNlIjoiYWRtaW5hcHAzIiwiYWN0aW9uIjoiTE9HT1VUIiwibm90QmVmb3JlIjoxNTg3MDQ3NTM3fQ.NplTHo8JuwtmUbpp3AHjM3c6rn7g_xGWegC-b8Gg7V2QoN9vPRb9oCc9fdD7qWKpXLgfNtvtTIJnIIP5O_ux7Jt_SQyNtwoPmf5k_EFmm7JSxPnVfVA36BJbGDJu_BiNbktGgpNVZR5HnAkawhsLLo05S0edFfnbs4N9a_4W_YM',
  logoutWrongKeyPairPayload: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkZKODZHY0YzalRiTkxPY280TnZaa1VDSVVtZllDcW9xdE9RZU1mYmhObEUifQ.eyJpYXQiOjE1NTc4NjE2NjgsInJlc291cmNlIjoiYWRtaW5hcHAyIiwiYWN0aW9uIjoiTE9HT1VUIiwibm90QmVmb3JlIjoxNTg3MDQ3NTM3fQ.aqNUXVbf2poQBj9V2oHTUiEn3NrUAbpVBt_70MC-l2_ihwaer8c93KhB3VDFZVVHDf_Jq-9_JVvwV755LXbtNOLXvptTXBQYyXFeu1LfwJTON217xzNlf0izm2tdl5qDyjcYNNX1TrltlraZIh2j96BsgDCRx8k_m2c_H_4xCfoU73eqehID5ob1wNXtT8372Xiykzrwotpe9oXPhSEHRT7r62IvqfiYMJ7iTPaffGz9_oeeMTlOrx9YB29M7Y5KHPjYKjRPR8caNFYCI9j1HoQiMKNkcn5oTH7aUUnNE8S8x-YIlxeXLP1SqVrB2Psf2PXbTsMDr4R4JaJikwn1wA',
  logoutIncompletePayload: '.eyJyZXNvdXJjZSI6Im5vZGVqcy1jb25uZWN0IiwiYWN0aW9uIjoiTE9HT1VUIiwibm90QmVmb3JlIjoxNTg3MDQ3NTM3fQ.',
  notBeforeValidPayload: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkZKODZHY0YzalRiTkxPY280TnZaa1VDSVVtZllDcW9xdE9RZU1mYmhObEUifQ.eyJpYXQiOjE1NTY2MTgzNTAsInJlc291cmNlIjoiYWRtaW5hcHA3IiwiYWN0aW9uIjoiUFVTSF9OT1RfQkVGT1JFIiwibm90QmVmb3JlIjoxNTg3MDQ3NTM3fQ.iLrZ6Z2FXZt3XuTbRWXJzmK281p33Py_hhkcevPyVsW3OhOli5CZsEZBSKXnUBOJgEN9HQXRoRUr4KWhbquoQi_wUIjp0Cog_0qC8JepCvz0FWhaProgtJxKjlYgiY3kzjMI4MDFfeTE2xrcXzJ5qbYxmhU1t07_7t4BHzm7C6o',
  notBeforeWrongKeyPairPayload: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IkZKODZHY0YzalRiTkxPY280TnZaa1VDSVVtZllDcW9xdE9RZU1mYmhObEUifQ.eyJpYXQiOjE1NTY2MTg2NjIsInJlc291cmNlIjoiYWRtaW5hcHA2IiwiYWN0aW9uIjoiUFVTSF9OT1RfQkVGT1JFIiwibm90QmVmb3JlIjoxNTg3MDQ3NTM3fQ.X0EoW-9N_6jOn9VFkm3HxTwZS2cCm0ChCH3ddYcAnVcugGSrvv1K5vQy9czlalvEnLZ_HpaWNWoBYA7hoqR5S600A-BSMHrb6oPt2B1JW8htgubD8NbJC2COsOGAbxLupO9YEP_oodzpAF5ikMB3Pm2g1e66BFvotSQHAtgg7HepzywvPrkYork44worrX2ByHVK4Y5Or6BWleEx1pa59dqmZNfupaL4pKSG9j7H9NM1YmEuKwjHr9PIyN7bPkx64LamI5aUIk5rjIM8plnxiayEgdCr9B6ag0xVoKggv3GV0m-XsRkbUPl91EbLQXwSCYdL5TQsvK5uJqkba9eiRA',
  notBeforeIncompletePayload: '.eyJyZXNvdXJjZSI6ImFkbWluYXBwNSIsImFjdGlvbiI6IlBVU0hfTk9UX0JFRk9SRSIsIm5vdEJlZm9yZSI6MTU4NzA0NzUzN30.'
}

export const dummyReply = {
  access_token: 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3RHg3UjFXSDA3S0JZM29aSExyRjRRZTBYNnJjOHpfWFU0dDBOZ19SWWhnIn0.eyJleHAiOjE2NzMyMTQ2ODMsImlhdCI6MTY3MzIxNDY4MSwianRpIjoiNmZlOTNlZTctMTZjYS00M2Q1LWE5NmQtMDBmZDc1MTJiMWQ1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9ub2RlanMtdGVzdCIsImF1ZCI6WyJwdWJsaWMtY2xpZW50IiwiY29uZmlkZW50aWFsLWNsaWVudCIsImFjY291bnQiXSwic3ViIjoiYjNlYWU0MjItMzU2OS00MDRiLWEyMTQtMDNhYzliYjdhOTc0IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicHVibGljLWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJlYTE3NjJiMS1lYzZhLTQ4MTctYTcxMS1kNjI0YzJmZGM2MmYiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiY29uZmlkZW50aWFsLWNsaWVudCI6eyJyb2xlcyI6WyJ0ZXN0Il19LCJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZWExNzYyYjEtZWM2YS00ODE3LWE3MTEtZDYyNGMyZmRjNjJmIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ0ZXN0LXVzZXIifQ.PHPjndD3pzbPE0au_lpXB41YS70Go9cdwnfNhDLvYphuFlCfl45j8lq7MRxw50VjXKDlUx848nO9mYWU_uCPTouhNvcGFD7T4bewSffB19-nwg8PG7vuEn5XQXW8QEsFByzNx20k34znpYM2qvbLFR_LhAqW6Ii7kOb9XHgKBNjHBiaVEqaDXVPE9z3Fi920YIB3O1FV1AQPqaUYCCmHUF_TXaUgd4jyddB1DAr-qHO3ZXUv2EsHDQerdRTT_rGIUa4gToza1UQlkQw6D20B-wvYe0-19ECqOOQmAJfAcfEqmjP0C6IAxfbT4sdZI6WUqo2u9yGyCSWwKM-V_L4bzw',
  expires_in: 2,
  refresh_expires_in: 1800,
  refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1NDE5NjY5NC05MTEwLTRhZDgtYjYxNy0wNjA0Y2E0MDI4YWYifQ.eyJleHAiOjE2NzMyMTY0ODEsImlhdCI6MTY3MzIxNDY4MSwianRpIjoiNmVjOWM4MTYtM2Y5Ni00MTY4LTk5OGItYjY3NjhjNTNkNDg1IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9ub2RlanMtdGVzdCIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9yZWFsbXMvbm9kZWpzLXRlc3QiLCJzdWIiOiJiM2VhZTQyMi0zNTY5LTQwNGItYTIxNC0wM2FjOWJiN2E5NzQiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoicHVibGljLWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJlYTE3NjJiMS1lYzZhLTQ4MTctYTcxMS1kNjI0YzJmZGM2MmYiLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZWExNzYyYjEtZWM2YS00ODE3LWE3MTEtZDYyNGMyZmRjNjJmIn0.SQiXXhqPrBZCGGYMvA8GVhRONhV6NDmiCL3J1bCQQh0',
  token_type: 'Bearer',
  id_token: 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3RHg3UjFXSDA3S0JZM29aSExyRjRRZTBYNnJjOHpfWFU0dDBOZ19SWWhnIn0.eyJleHAiOjE2NzMyMTQ2ODMsImlhdCI6MTY3MzIxNDY4MSwiYXV0aF90aW1lIjowLCJqdGkiOiIxMTJkYTY1ZC02ZjVmLTQ2NDktODBjMi1lNTE4NjE4ODExYjAiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL25vZGVqcy10ZXN0IiwiYXVkIjoicHVibGljLWNsaWVudCIsInN1YiI6ImIzZWFlNDIyLTM1NjktNDA0Yi1hMjE0LTAzYWM5YmI3YTk3NCIsInR5cCI6IklEIiwiYXpwIjoicHVibGljLWNsaWVudCIsInNlc3Npb25fc3RhdGUiOiJlYTE3NjJiMS1lYzZhLTQ4MTctYTcxMS1kNjI0YzJmZGM2MmYiLCJhdF9oYXNoIjoiV1lLc29XSjNyaUxtYmpFcnFCZDAtdyIsInNpZCI6ImVhMTc2MmIxLWVjNmEtNDgxNy1hNzExLWQ2MjRjMmZkYzYyZiIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdC11c2VyIn0.A6pCGlLcIQGNs6uJPMGjkyuSZ_PD7mFjB-ZT-AzpVKwwLODAn86_2JfD7dCFA773bBJ-MAactn1hIRxqFVKqtG8FbRbzFEBk4Fm5UQNcXjghOKdDQOrJhltrVA5u_Nkr52MqxONWyJMFdF3VFilQ4ZAOQdTtzWvGy2pBqjgl1EvZQxNloCRidQxtVg-wxZhSt_wv78NeA1MyxpWun8tPOYVFuMts-GCb5IhNEHgqiKfYNwZa1xmptjRxLF2j8u-u5KsOu4O_kdJLgJ-RUmFrDcL95tknwh8BDxDn6Wu8dlu-rbwie4U_pWv0rMi87eo2lAR7SnzmQCKLOtC3GjFLSw',
  'not-before-policy': 1_462_208_947,
  session_state: 'ea1762b1-ec6a-4817-a711-d624c2fdc62f',
  scope: 'openid profile email'
}
