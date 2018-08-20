const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken');
const crypto = require('crypto')
const mailer = require('../../modules/mailer')

const authConfig = require('../../config/auth');

const User = require('../models/user')

const router = express.Router()

const generateToken = (params = {}) => {
  return jwt.sign(params, authConfig.secret, {
    expiresIn: 86400,
  })
}

router.post('/register', async (req, res) => {
  const { email } = req.body

  try {
    if (await User.findOne({ email }))
      return res.status(400).send({ error: 'Email already exists' })

    const user = await User.create(req.body)

    user.password = undefined

    return res.send({
      user,
      token: generateToken({ id: user.id })
    })
  } catch (err) {
    return res.status(400).send({ error: 'Registration failed: ' + err })
  }
})

router.post('/authenticate', async (req, res) => {

  const {email, password} = req.body

  const user = await User.findOne({ email }).select('+password')

  if (!user) return res.status(400).send({ error: 'User not found' })

  if (!await bcrypt.compare(password, user.password)) return res.status(400).send({ error: 'Invalid password' })

  user.password = undefined

  res.send({
    user,
    token: generateToken({ id: user.id })
  })

})

router.post('/forgot', async (req, res) => {
  const { email } = req.body

  try {
    const user = await User.findOne({ email })

    if (!user) return res.status(400).send({ error: 'E-mail not found' })

    const token = crypto.randomBytes(20).toString('hex')

    const now = new Date()
    now.setHours(now.getHours() + 1)

    await User.findByIdAndUpdate(user.id, {
      '$set': {
        passwordResetToken: token,
        passwordResetExpires: now
      }
    })

    mailer.sendMail({
      to: email,
      from: 'system@api.com',
      template: 'auth/forgot',
      context: { token }
    }, (err) => {
      console.log(err);
      if (err) return res.status(400).send({ error: 'Cannot send forgot password email' })

      return res.send('Check your email')
    })

  } catch (e) {
    res.status(400).send({ error: 'Error on forgot password' })
  }
})

router.post('/reset', async (req, res) => {
  try {
    const { email, token, password } = req.body

    const user = await User.findOne({ email })
    .select('+passwordResetToken passwordResetExpires')

    if (!user) return res.status(400).send({ error: 'E-mail not found' })

    if (token != user.passwordResetToken) return res.status(400).send({ error: 'Token invalid' })

    const now = new Date()

    if (now > user.passwordResetExpires) return res.status(400).send({ error: 'Token expired, generate a new one' })

    user.password = password

    await user.save()

    res.send('Password was successful changed')
  } catch (e) {
    res.status(400).send({ error: 'Error on reset password' })
  }
})

module.exports = app => app.use('/auth', router)
