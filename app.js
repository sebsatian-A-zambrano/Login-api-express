import express from 'express'
import { PORT, SECRETE_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import session from 'express-session'

const app = express()
// Configure session
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}))
app.set('view engine', 'ejs')
app.use(express.json())
app.use(cookieParser())

app.get('/', (req, res) => {
  const token = req.cookies.access_token
  const username = req.session.username || null
  res.render('index', { token, username })
})

app.get('/example', (req, res) => {
  const token = req.cookies.access_token
  if (!token) {
    return res.status(403).send({ message: 'acesso não autorizado' })
  }
  try {
    const data = jwt.verify(token, SECRETE_JWT_KEY)
    const username = req.session.username || null
    const viewData = { ...data, username }
    res.render('example', viewData)
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(403).send({ message: 'Token expirado' })
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).send({ message: 'Token inválido' })
    }
    return res.status(403).send({ message: 'acesso não autorizado' })
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign({ id: user._id, username: user.username }, SECRETE_JWT_KEY, {
      expiresIn: '1h'
    })
    // Set the cookie
    res.cookie('access_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' })
    // Set the username in the session
    req.session.username = user.username
    // Send the response
    res.json({ success: true, redirect: '/example', user, token })
  } catch (error) {
    res.status(401).json({ success: false, message: error.message })
  }
})
app.post('/register', async (req, res) => {
  const { username, password } = req.body
  console.log(req.body)

  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (error) {
    res.status(400).send(error.message)
  }
})

app.get('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .clearCookie('username')
    .redirect('/')
})

app.get('/protected', (req, res) => {})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
