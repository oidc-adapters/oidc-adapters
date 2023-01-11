import { memoize } from './memoize.util.js'
import { fn } from 'jest-mock'

describe('memoize', () => {
  const apply = (a: string | string[] | undefined) => {
    return `memoize:${a}`
  }

  it('should give same result as original function', () => {
    const memoizedApply = memoize(apply)
    expect(memoizedApply('foo')).toEqual(apply('foo'))
    expect(memoizedApply(['foo', 'bar'])).toEqual(apply(['foo', 'bar']))
  })

  it('should give invoke function only once for a parameter set', () => {
    const applySpy = fn(apply)

    const memoizedApply = memoize(applySpy)
    memoizedApply('foo')
    memoizedApply('foo')
    memoizedApply('foo')
    memoizedApply('foo')

    expect(applySpy).toHaveBeenCalledTimes(1)
  })
})
