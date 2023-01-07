export default {
  transform: {
    '^.+\\.ts$': ['@swc/jest']
  },
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1'
  },
  testEnvironment: 'node',
  testRegex: ['.*\\.spec\\.ts$'],
  maxWorkers: 4
}
