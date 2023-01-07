# OpenID Connect Adapters for Node.js

Those packages assumes fetch API is available.

Fetch API is available in Node.js >= 18.

To run or Node.js 16, you should use `node-fetch` npm package and register it globally.

```typescript
import fetch from 'node-fetch'

global.fetch = fetch
```
