var test = require('tape')
var townshipAccess = require('township-access')
var townshipAuth = require('township-auth')
var basic = require('township-auth/basic')
var memdb = require('memdb')

var townshipToken = require('./index')

test('sign and verify a token', function (t) {
  var tokens = townshipToken({ secret: 'this is secret' })

  var tokenData = {
    auth: {
      basic: {
        key: 'pizza',
        email: 'pizza@pizza.com'
      }
    },
    access: {
      key: 'pizza',
      scopes: ['pizza:eat']
    },
    data: {
      arbitrary: 'data'
    }
  }

  var token = tokens.sign(tokenData)
  var data = tokens.verify(token)
  t.ok(token)
  t.ok(data)
  t.equal(data.auth.key, tokenData.auth.key)
  t.end()
})

test('use with township-auth and township-access', function (t) {
  var db = memdb()
  var tokens = townshipToken({ secret: 'not a secret' })
  var access = townshipAccess(db)
  var auth = townshipAuth(db, {
    providers: { basic: basic }
  })

  var creds = { basic: { email: 'hi@example.com', password: 'oops' } }

  auth.create(creds, function (err, authData) {
    t.notOk(err)
    t.ok(authData)

    access.create(authData.key, ['site:read'], function (err, accessData) {
      t.notOk(err)
      t.ok(accessData)

      var token = tokens.sign({
        auth: authData,
        access: accessData
      })

      t.ok(token)
      var data = tokens.verify(token)
      t.ok(data)
      t.equal(data.auth.basic.email, creds.basic.email)
      t.equal(data.access.scopes[0], 'site:read')
      t.end()
    })
  })
})
