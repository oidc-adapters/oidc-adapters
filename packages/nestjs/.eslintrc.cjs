// eslint-disable-next-line n/no-unpublished-require
const config = require('../.eslintrc.base.cjs')

config.parserOptions = {
  ...config.parserOptions,

  tsconfigRootDir: __dirname,
  project: ['./tsconfig.json']
}

module.exports = config
