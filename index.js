var jwt = require('jsonwebtoken')

module.exports = function townshipToken (options) {
  options = options || {}
  var secret = options.secret || 'not a secret'
  var token = {}

  token.sign = function sign (payload) {
    if (!payload.auth) throw new Error('auth object is required')
    if (!payload.access) throw new Error('access object is required')
    return jwt.sign(payload, secret)
  }

  token.verify = function verify (token) {
    return jwt.verify(token, secret)
  }

  return token
}
