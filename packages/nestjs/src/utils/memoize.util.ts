export function memoize<R> (function_: (key: string | string[] | undefined) => R) {
  const cache: Map<string | string[] | undefined, R> = new Map()
  return (key: string | string[] | undefined) => {
    const cacheKey = Array.isArray(key) ? [`[${key.join(',')}]`] : key

    const cached = cache.get(cacheKey)
    if (cached !== undefined) {
      return cached
    } else {
      const result = function_(key)
      cache.set(cacheKey, result)
      return result
    }
  }
}
