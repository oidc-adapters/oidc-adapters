import settings from './config.js'

const defaultSettings = {
  username: 'test-admin',
  password: 'password',
  grant_type: 'password',
  client_id: 'admin-app'
}

const tokenUrl = 'protocol/openid-connect/token'

/**
 Requests a new Keycloak Access Token
 @param {string} baseUrl - The baseurl for the Keycloak server - ex: http://localhost:8080/auth,
 @param {string} realmName - the name of the realm to login to - defaults to 'master'
 @param {object} parameters - an object containing the settings
 @param {string} parameters.username - The username to login to the keycloak server - ex: admin
 @param {string} parameters.password - The password to login to the keycloak server - ex: *****
 @param {string} parameters.grant_type - the type of authentication mechanism - ex: password,
 @param {string} parameters.client_id - the id of the client that is registered with Keycloak to connect to - ex: admin-cli
 @returns {Promise} A promise that will resolve with the Access Token String.
 @instance
 @example

 const tokenRequester = require('keycloak-request-token');
 const baseUrl = 'http://127.0.0.1:8080/auth';
 const settings = {
      username: 'admin',
      password: 'admi',
      grant_type: 'password',
      client_id: 'admin-cli'
  };

 tokenRequester(baseUrl, settings)
 .then((token) => {
      console.log(token);
    }).catch((err) => {
      console.log('err', err);
    });
 */
async function getToken (baseUrl: string, realmName = 'master', parameters: Record<string, string> = {}) {
  const response = await fetch(`${baseUrl}/realms/${realmName}/${tokenUrl}`, {
    method: 'post',
    headers: { 'Content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(parameters)
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`response.status: ${text}`)
  }

  const json = await response.json() as { access_token?: string }
  return json.access_token
}

export default (realmName?: string, options?: Record<string, string>) => {
  const tokenSettings: Record<string, string> = Object.assign({}, defaultSettings, options)
  return getToken(settings.baseUrl, realmName, tokenSettings)
}
