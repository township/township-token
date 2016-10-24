<!-- Generated by documentation.js. Update this documentation by updating the source code. -->

# townshipToken

Initialize the `townshipToken` module

**Parameters**

-   `db` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** – An instance of a leveldb via [level](https://https://github.com/Level/level)
-   `options` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** 
    -   `options.secret` **[string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)** – Secret used for signing tokens

**Examples**

```javascript
var level = require('level')
var townshipToken = require('township-token')

var db = level('./db')
var tokens = townshipToken(db, { secret: process.env.TOWNSHIP_SECRET })
```

# tokens.sign

Sign a payload to create a tokens.

**Parameters**

-   `payload` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** 
    -   `payload.auth` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** The data from the [township-auth](https://github.com/township/township-auth) module for a user
    -   `payload.access` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** The data from the [township-access](https://github.com/township/township-access) module for a user
    -   `payload.data` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** – Arbitrary data related to the user.
-   `options` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** **Optional.**
    -   `options.secret` **[string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)** – **Optional.** Override the secret passed into `townshipToken`
    -   `options.expiresIn` **[string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)** – **Optional.** _Default:_ `5h`. Specify when the token expires. Uses the [ms](https://github.com/zeit/ms) module.

**Examples**

```javascript
var token = tokens.sign({
  auth: { basic: { key: 'example', email: 'email@example.com' } },
  access: { scopes: ['site:read', 'site:edit'] },
  data: { arbitrary: 'data' }
})
```

# tokens.verify

Verify a tokens.

**Parameters**

-   `token` **[string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)** The encoded token that was created by `tokens.sign`.
-   `options` **[object](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object)** **Optional.**
    -   `options.secret` **[string](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String)** **Optional.** Override the secret passed into `townshipToken`
-   `callback` **[function](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/function)** \-

# tokens.invalidate

Invalidate a token by storing it in the invalid list.

# tokens.cleanupInvalidList

Remove expired tokens from the list of invalid tokens.