const jwt = require('jsonwebtoken');

const authConfig = require('../config/auth');

module.exports = (req, res, next) => {
  const authHeader = req.headers.authorization

  // check if authorization was provided
  if (!authHeader) return res.status(401).send({ error: 'No token provided' })

  const parts = authHeader.split(' ')

  // Token has two parts
  if (parts.length != 2) return res.status(401).send({ error: 'Token error' })

  const [shema, token] = parts

  // All token begin with Bearer string
  if (shema.toLowerCase() != 'bearer') return res.status(401).send({ error: 'Token malformatted' })

  jwt.verify(token, authConfig.secret, (error, decoded) => {
    if (error) return res.status(401).send({ error: 'Token invalid' })

    req.userId = decoded.id
    return next()
  })

};
