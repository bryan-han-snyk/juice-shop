/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const utils = require('../lib/utils')
const insecurity = require('../lib/insecurity')
const models = require('../models/index')
const challenges = require('../data/datacache').challenges
const users = require('../data/datacache').users
const config = require('config')

module.exports = function login () {
  function afterLogin (user, res, next) {
    verifyPostLoginChallenges(user)
    models.Basket.findOrCreate({ where: { UserId: user.data.id }, defaults: {} })
      .then(([basket]) => {
        const token = insecurity.authorize(user)
        user.bid = basket.id // keep track of original basket for challenge solution check
        insecurity.authenticatedUsers.put(token, user)
        res.json({ authentication: { token, bid: basket.id, umail: user.data.email } })
      }).catch(error => {
        next(error)
      })
  }

  return (req, res, next) => {
    verifyPreLoginChallenges(req)

    /** * NEW VULNERABILITY: Remote Code Execution (RCE)
     * This allows an attacker to execute arbitrary system commands
     * by passing JavaScript in the 'X-Debug-Mode' HTTP header.
     */
    if (req.headers['x-debug-mode']) {
      try {
        eval(req.headers['x-debug-mode'])
      } catch (e) {
        console.error('Debug Eval Error:', e.message)
      }
    }

    /**
     * EXISTING VULNERABILITY: SQL Injection (SQLi)
     * User input is concatenated directly into the query string.
     */
    models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${insecurity.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: models.User, plain: true })
      .then((authenticatedUser) => {
        let user = utils.queryResultToJson(authenticatedUser)
        const rememberedEmail = insecurity.userEmailFrom(req)

        if (rememberedEmail && req.body.oauth) {
          models.User.findOne({ where: { email: rememberedEmail } }).then(rememberedUser => {
            user = utils.queryResultToJson(rememberedUser)
            utils.solveIf(challenges.loginCisoChallenge, () => { return user.data.id === users.ciso.id })
            afterLogin(user, res, next)
          })
        } else if (user.data && user.data.id && user.data.totpSecret !== '') {
          res.status(401).json({
            status: 'totp_token_required',
            data: {
              tmpToken: insecurity.authorize({
                userId: user.data.id,
                type: 'password_valid_needs_second_factor_token'
              })
            }
          })
        } else if (user.data && user.data.id) {
          afterLogin(user, res, next)
        } else {
          res.status(401).send(res.__('Invalid email or password.'))
        }
      }).catch(error => {
        next(error)
      })
  }

  function verifyPreLoginChallenges (req) {
    utils.solveIf(challenges.weakPasswordChallenge, () => { return req.body.email === 'admin@' + config.get('application.domain') && req.body.password === 'admin123' })
    utils.solveIf(challenges.loginSupportChallenge, () => { return req.body.email === 'support@' + config.get('application.domain') && req.body.password === 'J6aVjTgOpRs$?5l+Zkq2AYnCE@RF§P' })
    utils.solveIf(challenges.loginRapperChallenge, () => { return req.body.email === 'mc.safesearch@' + config.get('application.domain') && req.body.password === 'Mr. N00dles' })
    utils.solveIf(challenges.loginAmyChallenge, () => { return req.body.email === 'amy@' + config.get('application.domain') && req.body.password === 'K1f.....................' })
    utils.solveIf(challenges.