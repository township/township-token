var test = require('tape')
var townshipAccess = require('township-access')
var townshipAuth = require('township-auth')
var basic = require('township-auth/basic')
var memdb = require('memdb')

var townshipToken = require('./index')

var publicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAvmJlA/DZl3SVKNl0OcyVbsMTOmTM
qU0Avhmcl6r8qxkBgjwArIxQr7G7v8m0LOeFIklnmF3sYAwA+8llHGFReV8ASW4w
5AUC8ngZThaH9xk6DQscaMmoEFPN5thWpNcwMgUFYovBtPLwtAZjYr9Se+UT/5k4
VltW7ko6SHbCfMgUUbU=
-----END PUBLIC KEY-----`

var privateKey = `-----BEGIN EC PRIVATE KEY-----
MIHbAgEBBEFmz7VMXRtCPTlBETqMMx/mokyA3xPXra2SkcA7Xh0N6sgne1rgSZNU
ngT6TR3XLfBOt5+p5GRW6p1FVtn+vtPyRKAHBgUrgQQAI6GBiQOBhgAEAL5iZQPw
2Zd0lSjZdDnMlW7DEzpkzKlNAL4ZnJeq/KsZAYI8AKyMUK+xu7/JtCznhSJJZ5hd
7GAMAPvJZRxhUXlfAEluMOQFAvJ4GU4Wh/cZOg0LHGjJqBBTzebYVqTXMDIFBWKL
wbTy8LQGY2K/UnvlE/+ZOFZbVu5KOkh2wnzIFFG1
-----END EC PRIVATE KEY-----`

test('sign and verify a token with secret', function (t) {
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

test('sign and verify a token with keypair', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { publicKey: publicKey, privateKey: privateKey, algorithm: 'ES512' })

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

test('clean up invalid tokens list with secret', function (t) {
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

test('clean up invalid tokens list with keys', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { publicKey: publicKey, privateKey: privateKey, algorithm: 'ES512' })
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

test('two tokens with same data made at different times are not the same', function (t) {
  var db = memdb()
  var tokens = townshipToken(db, { secret: 'not a secret' })

  var token1 = tokens.sign({
    auth: { basic: { key: 'example', email: 'email@example.com' } },
    access: { scopes: ['site:read', 'site:edit'] },
    data: { arbitrary: 'data' }
  })

  setTimeout(function () {
    var token2 = tokens.sign({
      auth: { basic: { key: 'example', email: 'email@example.com' } },
      access: { scopes: ['site:read', 'site:edit'] },
      data: { arbitrary: 'data' }
    })

    t.notEqual(token1, token2)
    t.end()
  }, 5000)
})
