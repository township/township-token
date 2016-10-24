# township-token

Create JWT tokens using township [auth](http://github.com/township/township-auth) & [access](http://github.com/township/township-access) data.

## Install

    npm i -g township-token

## Examples

Basic example:

```js
var level = require('level')
var townshipToken = require('township-token')

var db = level('./db')
var tokens = townshipToken(db, { secret: process.env.TOWNSHIP_SECRET })

// create a token
var token = tokens.sign({
  auth: { basic: { key: 'example', email: 'email@example.com' } },
  access: { scopes: ['site:read', 'site:edit'] },
  data: { arbitrary: 'data' }
})

// verify and decode a token
tokens.verify(token, function (err, data) {
  // use the data from the token
})
```

Full example with [township-auth](http://github.com/township/township-auth) & [township-access](http://github.com/township/township-access):

```js
var level = require('level')
var townshipToken = require('township-token')
var townshipAccess = require('township-access')
var townshipAuth = require('township-auth')
var basic = require('township-auth/basic')

var db = level('db')
var tokens = townshipToken(db, { secret: process.env.TOWNSHIP_SECRET })
var access = townshipAccess(db)
var auth = townshipAuth(db, {
  providers: { basic: basic }
})

var creds = { basic: { email: 'hi@example.com', password: 'oops' } }

// create an auth record
auth.create(creds, function (err, authData) {

  // create an access record
  access.create(account.key, ['site:read'], function (err, accessData) {

    // create a token for a client to use
    var token = tokens.sign({
      auth: authData,
      access: accessData
    })

    // verify the token when received from a client
    tokens.verify(token, function (err, data) {
      // use the data from the token
    })
  })
})
```

## API

Read the API docs for this module in [docs/API.md](docs/API.md)

## See also

-   [township-auth](https://github.com/township/township-auth) - manage authentication credentials
-   [township-access](https://github.com/township/township-access) - manage access authorization scopes

## License

[MIT](LICENSE.md)
