import https from 'node:https'
import http from 'node:http'

export function getProtocol (options: https.RequestOptions) {
  return options.protocol === 'https:' ? https : http
}
