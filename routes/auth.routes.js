const { Router } = require('express')
const config = require('config')

/*
  express
  mongoose - mongoDB api
  bcrypjs - hash password and check isMatch(password/hashed)
  express-validator
*/

const bcrypt = require('bcryptjs')
const { check, validationResult } = require('express-validator')

const jwt = require('jsonwebtoken')
const JWT_SECRET = config.get('jwt-secret')

const User = require('../models/User')
const router = Router()

// /api/auth/sign-up
router.post(
  '/sign-up',
  [
    check('email', 'Bad email').isEmail(),
    check('password', 'Bad password').isLength({ min: 6 }),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Bad sign-up data',
        })
      }
      const { email, password } = req.body
      const candidate = await User.findOne({ email })
      if (candidate) {
        res.status(400).json({ message: 'user is already registered ' })
      }
      const hashedPassword = await bcrypt.hash(password, 12)
      const user = new User({ email, password: hashedPassword })
      await user.save()
      // 201 -create status
      res.status(201).json({ message: 'User created' })
    } catch (e) {
      res.status(500).json({ message: 'Something wrong.. Try again.' })
    }
  }
)

// /api/auth/sign-in
router.post(
  '/sign-in',
  [
    check('email', 'Bad email')
      .normalizeEmail({ gmail_remove_dots: false })
      .isEmail(),
    check('password', 'password is exist').exists(),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (errors.isEmpty()) {
        return res.status(400).json({
          errors: errors.array(),
          message: 'Bad sign-in data',
        })
      }

      const { email, password } = req.body

      const user = await User.findOne({ email })
      if (!user) {
        return res.status(400).json({ message: 'User not found' })
      }
      // check passwords is Match
      const isMatch = await bcrypt.compare(password, user.password)
      if (!isMatch) {
        return res.status(400).json({
          // ? bad practice is say user what is wrong.
          message: 'wrong password',
        })
      }
      const token = jwt.sign(
        { userId: user.id, userEmail: user.email },
        JWT_SECRET,
        { expiresIn: '1h' } // token end work after 1h
      )
      //default status 200
      res.json({ token, userId: user.id })
    } catch (e) {
      res.status(500)
    }
  }
)
module.exports = router
