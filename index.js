var assert = require('assert')
var jwt = require('jsonwebtoken')
var sublevel = require('subleveldown')
var through = require('through2')

/**
* Initialize the `townshipToken` module
* @name townshipToken
* @param {object} db – An instance of a leveldb via [level](https://https://github.com/Level/level)
* @param {object} options
* @param {string} options.secret – Secret used for signing tokens
* @example
* var level = require('level')
* var townshipToken = require('township-token')
*
* var db = level('./db')
* var tokens = townshipToken(db, { secret: process.env.TOWNSHIP_SECRET })
**/
module.exports = function townshipToken (maindb, options) {
  options = options || {}
  var secret = options.secret || 'not a secret'
  var db = sublevel(maindb, 'township-token')
  var tokens = {}
  tokens.db = db

  /**
  * Sign a payload to create a token.
  * @name tokens.sign
  * @param {object} payload
  * @param {object} payload.auth - The data from the [township-auth](https://github.com/township/township-auth) module for a user
  * @param {object} payload.access - The data from the [township-access](https://github.com/township/township-access) module for a user
  * @param {object} payload.data – Arbitrary data related to the user.
  * @param {object} options - **Optional.**
  * @param {string} options.secret – **Optional.** Override the secret passed into `townshipToken`
  * @param {string} options.expiresIn – **Optional.** _Default:_ `5h`. Specify when the token expires. Uses the [ms](https://github.com/zeit/ms) module.
  * @example
  * var token = tokens.sign({
  *   auth: { basic: { key: 'example', email: 'email@example.com' } },
  *   access: { scopes: ['site:read', 'site:edit'] },
  *   data: { arbitrary: 'data' }
  * })
  **/
  tokens.sign = function sign (payload, options) {
    assert.equal(typeof payload, 'object', 'township-token: payload object is required')
    assert.equal(typeof payload.auth, 'object', 'township-token: payload.auth object is required')
    assert.equal(typeof payload.access, 'object', 'township-token: payload.access object is required')

    options = options || {}
    options.expiresIn = options.expiresIn || '5h'
    secret = options.secret || secret
    return jwt.sign(payload, secret, options)
  }

  /**
  * Verify a token.
  * @name tokens.verify
  * @param {string} token - The encoded token that was created by `tokens.sign`.
  * @param {object} options - **Optional.**
  * @param {string} options.secret - **Optional.** Override the secret passed into `townshipToken`
  * @param {function} callback
  **/
  tokens.verify = function verify (token, options, callback) {
    assert.equal(typeof token, 'string', 'township-token: token parameter must be a string')

    if (typeof options === 'function') {
      callback = options
      options = {}
    }

    options = options || {}
    secret = options.secret || secret

    try {
      var data = jwt.verify(token, secret)
      db.get(token, function (err) {
        if (!err) return callback(new Error('Token is invalid'))
        return callback(null, data)
      })
    } catch (jwterr) {
      callback(jwterr)
    }
  }

  /**
  * Invalidate a token by storing it in the invalid list.
  * @name tokens.invalidate
  * @param {string} token - The encoded token that was created by `tokens.sign`.
  * @param {function} callback
  **/
  tokens.invalidate = function invalidate (token, callback) {
    assert.equal(typeof token, 'string', 'township-token: token parameter must be a string')
    assert.equal(typeof callback, 'function', 'township-token: callback function is required')
    db.put(token, token, callback)
  }

  /**
  * Remove expired tokens from the list of invalid tokens.
  * @name tokens.cleanupInvalidList
  * @param {object} options - **Optional.**
  * @param {string} options.secret - **Optional.** Override the secret passed into `townshipToken`
  * @param {function} callback
  **/
  tokens.cleanupInvalidList = function cleanupInvalidList (options, callback) {
    if (typeof options === 'function') {
      callback = options
      options = {}
    }

    options = options || {}
    secret = options.secret || secret
    db.createReadStream().pipe(through.obj(each, end))

    function each (token, enc, next) {
      try {
        jwt.verify(token.key, secret)
      } catch (jwterr) {
        return db.del(token.key, function (err) {
          if (err) return callback(err)
          next()
        })
      }
      this.push(token)
      next()
    }

    function end () {
      callback()
    }
  }

  return tokens
}
