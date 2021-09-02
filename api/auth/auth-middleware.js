const usersModel = require("../users/users-model");
const {body,validationResult} = require("express-validator");

const checkPayloadShape = [
  body("username").isString().withMessage({message:"username is required",status:422}),
  body("password").isString().withMessage({message:"Password must be longer than 3 chars",status:422}).isLength({min:3}).withMessage({message:"Password must be longer than 3 chars",status:422}),
  (req,res,next)=>{
    const errors = validationResult(req);
    if(errors.isEmpty()){
      return next();
    }
    else{
      const {message,status} = errors.array()[0].msg;
      return res.status(status).json({message});
    }
  }
]

/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req,res,next) {
  if(req.session && req.session.user){
    next();
  }
  else{
    res.status(401).json({message:`You shall not pass!`});
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req,res,next) {
  const {username} = req.body;
  const rows = await usersModel.findBy({username});
  if(rows.length === 0){
    next();
  }
  else{
    res.status(422).json({message:"Username taken"});
  }
}

/*
  If the username in req.body does NOT exist in the database

  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req,res,next) {
  const {username} = req.body;
  const rows = await usersModel.findBy({username});
  if(rows.length === 1){
    req.user = rows[0];
    next();
  }
  else{
    res.status(401).json({message:`Invalid credentials`});
  }

}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/


// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkUsernameFree,
  checkPayloadShape,
  checkUsernameExists
}