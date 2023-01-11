import { Octokit } from '@octokit/rest'
import { mkdir, symlink } from 'node:fs/promises'
import gunzip from 'gunzip-maybe'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { pipeline } from 'node:stream/promises'
import type tar from 'tar-fs'
import { extract } from 'tar-fs'

const DIR_NAME = path.dirname(fileURLToPath(import.meta.url))
const SERVER_DIR = path.resolve(DIR_NAME, '../server')
const SCRIPT_EXTENSION = process.platform === 'win32' ? '.bat' : '.sh'

await startServer()

async function symlinkImport () {
  const dataDirectory = path.resolve(SERVER_DIR, 'data')

  const dataDirectoryExists = fs.existsSync(dataDirectory)
  if (!dataDirectoryExists) {
    await mkdir(dataDirectory)
  }

  const importDirectory = path.resolve(dataDirectory, 'import')

  const importDirectoryExists = fs.existsSync(importDirectory)
  if (!importDirectoryExists) {
    await symlink(path.resolve(SERVER_DIR, '../../../docker-oidc-adapters/keycloak/import'), importDirectory)
  }
}

async function startServer () {
  await downloadServer()

  await downloadProvider('org.ow2.asm', 'asm', '7.3.1')
  await downloadProvider('org.ow2.asm', 'asm-commons', '7.3.1')
  await downloadProvider('org.ow2.asm', 'asm-tree', '7.3.1')
  await downloadProvider('org.ow2.asm', 'asm-util', '7.3.1')
  await downloadProvider('org.openjdk.nashorn', 'nashorn-core', '15.4')

  await symlinkImport()

  console.info('Starting server…')

  const arguments_ = process.argv.slice(2)
  const child = spawn(
    path.join(SERVER_DIR, `bin/kc${SCRIPT_EXTENSION}`),
    ['start-dev', ...arguments_],
    {
      env: {
        KEYCLOAK_ADMIN: 'admin',
        KEYCLOAK_ADMIN_PASSWORD: 'admin',
        ...process.env
      }
    }
  )

  child.stdout.pipe(process.stdout)
  child.stderr.pipe(process.stderr)
}

async function downloadServer () {
  const directoryExists = fs.existsSync(SERVER_DIR)

  if (directoryExists) {
    console.info('Server installation found, skipping download.')
    return
  }

  console.info('Downloading and extracting server…')

  const nightlyAsset = await getNightlyAsset()
  if (!nightlyAsset) {
    throw new Error('No nightly asset found to download Keycloak Server')
  }

  const assetStream = await getAssetAsStream(nightlyAsset)
  if (!assetStream) {
    throw new Error('Nightly asset is empty')
  }

  await extractTarball(assetStream as unknown as Parameters<typeof pipeline>[0], SERVER_DIR, { strip: 1 })
}

async function downloadProvider (groupId: string, artifactId: string, version: string) {
  const jarPath = path.join(SERVER_DIR, 'providers', `${artifactId}.jar`)

  const jarExists = fs.existsSync(jarPath)

  if (jarExists) {
    console.info(`${groupId}:${artifactId}:${version} provider found, skipping download.`)
    return
  }

  console.info(`Downloading and extracting provider ${groupId}:${artifactId}:${version} provider…`)

  const url = `https://repo1.maven.org/maven2/${groupId.replaceAll('.', '/')}/${artifactId}/${version}/${artifactId}-${version}.jar`

  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`An error has occured while downloading ${groupId}:${artifactId}:${version} provider (${response.status} ${response.statusText}) [${url}]`)
  }
  if (!response.body) {
    throw new Error('Empty body')
  }

  const fileStream = fs.createWriteStream(jarPath)
  const writableStream = new WritableStream<Uint8Array>({
    write (chunk) {
      fileStream.write(chunk)
    }
  })

  await response.body.pipeTo(writableStream)
}

async function getNightlyAsset () {
  const api = new Octokit()
  const release = await api.repos.getReleaseByTag({
    owner: 'keycloak',
    repo: 'keycloak',
    tag: 'nightly'
  })

  return release.data.assets.find(
    ({ name }) => name === 'keycloak-999-SNAPSHOT.tar.gz'
  )
}

async function getAssetAsStream (asset: Awaited<ReturnType<Octokit['repos']['getRelease']>>['data']['assets'][0]) {
  const response = await fetch(asset.browser_download_url)

  if (!response.ok) {
    throw new Error('Something went wrong requesting the nightly release.')
  }

  return response.body
}

async function extractTarball (stream: Parameters<typeof pipeline>[0], path: string, options?: tar.ExtractOptions) {
  return pipeline(stream, gunzip(), extract(path, options))
}
