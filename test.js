var test = require('tape')
var townshipAccess = require('township-access')
var townshipAuth = require('township-auth')
var basic = require('township-auth/basic')
var memdb = require('memdb')

var townshipToken = require('./index')

test('sign and verify a token', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { secret: 'not a secret' })

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
  tokens.verify(token, function (err, data) {
    t.notOk(err)
    t.ok(token)
    t.ok(data)
    t.equal(data.auth.key, tokenData.auth.key)
    t.end()
  })
})

test('use with township-auth and township-access', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { secret: 'not a secret' })
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
      tokens.verify(token, function (err, data) {
        t.notOk(err)
        t.ok(data)
        t.equal(data.auth.basic.email, creds.basic.email)
        t.equal(data.access.scopes[0], 'site:read')
        t.end()
      })
    })
  })
})

test('invalidate token', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { secret: 'not a secret' })
  var token = tokens.sign({
    auth: { basic: { key: 'example', email: 'email@example.com' } },
    access: { scopes: ['site:read', 'site:edit'] },
    data: { arbitrary: 'data' }
  })

  tokens.invalidate(token, function (err) {
    t.notOk(err)
    tokens.db.get(token, function (err, val) {
      t.notOk(err)
      t.equal(token, val)
      t.end()
    })
  })
})

test('clean up invalid tokens list', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { secret: 'not a secret' })
  var token = tokens.sign({
    auth: { basic: { key: 'example', email: 'email@example.com' } },
    access: { scopes: ['site:read', 'site:edit'] },
    data: { arbitrary: 'data' }
  }, {
    expiresIn: '1s'
  })

  tokens.invalidate(token, function (err) {
    t.notOk(err, 'no error from tokens.invalidate')
    setTimeout(function () {
      tokens.cleanupInvalidList(function (err) {
        t.notOk(err, 'no error from tokens.cleanupInvalidList')
        tokens.db.get(token, function (err, val) {
          t.equal(err.name, 'NotFoundError')
          t.end()
        })
      })
    }, 1500)
  })
})
