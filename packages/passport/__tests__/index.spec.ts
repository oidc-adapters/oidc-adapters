import { HelloWorld } from '../src/index.js'

describe('index.ts', function () {
  it('hello key should contain world', () => {
    expect(new HelloWorld().hello).toEqual('World')
  })
})
