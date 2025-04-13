import DBLocal from 'db-local'

import crypto from 'crypto'
import bcrypt from 'bcrypt'

import { SAL } from './config.js'

const { Schema } = new DBLocal({ path: './db.json' })

const User = Schema('users', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    Validation.username(username) // Validar username
    Validation.password(password) // Validar password

    const user = User.findOne({ username })
    if (user) throw new Error('El username ya existe')

    const id = crypto.randomUUID()
    const ahshedPassword = await bcrypt.hash(password, SAL) // hashSync → bloquea el thread principal

    User.create({ _id: id, username, password: ahshedPassword }).save()

    return { id }
  }

  static async login ({ username, password }) {
    Validation.username(username) // Validar username
    Validation.password(password) // Validar password

    const user = User.findOne({ username })
    if (!user) throw new Error('El username no existe')

    const isValidPassword = await bcrypt.compare(password, user.password) // compareSync → bloquea el thread principal
    if (!isValidPassword) throw new Error('El password es incorrecto')

    const { password: _, ...userWithoutPassword } = user
    return userWithoutPassword
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('username debe ser un string')
    if (username.length < 3) throw new Error('El username debe tener al menos 3 caracteres')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('la password debe ser un string')
    if (password.length < 6) throw new Error('El password debe tener al menos 6 caracteres')
  }
}
