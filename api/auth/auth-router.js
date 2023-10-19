const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const User = require('../users/users-model')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

router.post("/register", validateRoleName, async (req, res, next) => {
  try{
  const {username, password, role_name} = req.body
  const hash = bcrypt.hashSync(password, 8)
  const newUser = await User.add({username, password: hash, role_name: role_name.trim()})
  res.status(201).json(newUser)
    }catch(err){
      next(err)
    }
      /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  try{
    const {username, password} = req.body
    const user = await User.findBy({username})
    if(bcrypt.compareSync(password, user.password)){
      const token = buildUserToken(user)
      res.json({message: `${username} is back!`, token})
    }else {
      next({status:401, message: 'invalid credentials'})
    }
    
  }catch(err){
    next(err)
  }
  
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

const buildUserToken = (user) =>{
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const options = {
    expiresIn : '1d',
  }
  return jwt.sign(payload, JWT_SECRET, options)
}

module.exports = router;
