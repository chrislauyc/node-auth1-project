// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const usersModel = require("../users/users-model");
const router = require("express").Router();
const bcrypt = require("bcryptjs");
const {  
  checkUsernameExists,
  checkUsernameFree,
  checkPayloadShape
} = require("./auth-middleware");
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post("/register",checkPayloadShape,checkUsernameFree,async(req,res,next)=>{
  try{
    req.body.password = bcrypt.hashSync(req.body.password);
    const {username,password} = req.body;
    const user = await usersModel.add({username,password});
    res.status(201).json(user);
  }
  catch(err){
    next(err);
  }
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post("/login",checkPayloadShape,checkUsernameExists,async(req,res,next)=>{
  try{
    const valid = bcrypt.compareSync(req.body.password,req.user.password);
    if(valid){
      req.session.user = req.user;
      res.status(200).json({message:`welcome ${req.body.username}!`});
    }
    else{
      res.status(401).json({message:"Invalid credentials"});
    }
  }
  catch(err){
    next(err);
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout",(req,res,next)=>{
  try{
    if(req.session && req.session.user){
      req.session.destroy((err)=>{
        if(err){
          res.status(200).json({message: err});
        }
        else{
          res.status(200).json({message: `logged out`});
        }
      })
    }
    else{
      res.status(200).json({message:"no session"});
    }
  }
  catch(err){
    next(err);
  }
});
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;