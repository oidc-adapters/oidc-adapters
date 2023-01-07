module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    sourceType: 'module'
  },
  extends: [
    'standard',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'plugin:n/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'plugin:promise/recommended',
    'plugin:jest/recommended',
    'plugin:unicorn/recommended'
  ],
  env: {
    es2021: true,
    node: true,
    jest: true
  },
  ignorePatterns: [
    'dist/',
    'coverage/'
  ],
  rules: {
    'no-process-exit': 'off', // duplicates with unicorn/no-process-exit
    'n/no-process-exit': 'off', // duplicates with unicorn/no-process-exit
    'no-use-before-define': 'off',
    'no-useless-constructor': 'off',
    'n/no-missing-import': 'off',
    'n/file-extension-in-import': ['error', 'always'],
    'jest/expect-expect': 'off',
    'unicorn/empty-brace-spaces': 'off',
    'unicorn/prefer-ternary': 'off',
    'unicorn/prefer-switch': 'off',
    'unicorn/no-negated-condition': 'off',
    '@typescript-eslint/consistent-type-imports': 'error',
    '@typescript-eslint/restrict-template-expressions': 'off',
    '@typescript-eslint/require-await': 'off'
  },
  settings: {
    'import/resolver': {
      typescript: {
        alwaysTryTypes: true
      }
    }
  },
  overrides: [
    {
      files: ['**/*.spec.*', '__tests__/**'],
      rules: {
        '@typescript-eslint/no-non-null-assertion': 'off',
        'unicorn/consistent-function-scoping': 'off',
        'n/no-unpublished-import': 'off',
        'unicorn/no-useless-undefined': 'off',
        '@typescript-eslint/no-unsafe-member-access': 'off'
      }
    },
    {
      files: ['**/*.cjs', '**/*.js'],
      rules: {
        '@typescript-eslint/no-var-requires': 'off',
        '@typescript-eslint/no-unsafe-assignment': 'off',
        '@typescript-eslint/no-unsafe-return': 'off',
        '@typescript-eslint/no-unsafe-call': 'off',
        '@typescript-eslint/no-unsafe-member-access': 'off',
        '@typescript-eslint/no-unsafe-argument': 'off'

      }
    }
  ]
}
