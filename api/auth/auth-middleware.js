const usersModel = require("../users/users-model");
const yup = require("yup");

const schema = yup.object().shape({
  username:yup.string().required("username is required"),
  password:yup.string().required("password is required").length().min(3, "Password must be longer than 3 chars")
});
async function checkPayloadShape(req,res,next){
  try{
    const {username,password} = req.body;
    await yup.reach(schema,"username",username);
    await yup.reach(schema,"password",password);
    next();
  }
  catch(err){
    res.status(400).json({message:err.errors[0]});
  }
};

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
    res.status(401).json({message:"You shall not pass!"});
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
  const rows = usersModel.findBy({username});
  if(rows.length === 1){
    req.user = rows[0];
    next();
  }
  else{
    res.status(401).json({message:"Invalid credentials"});
  }

}

/*
  If password is missing from req.body, or if it's 3 chars or shorter

  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
async function checkPasswordLength(req,res,next) {
  try{
    await yup.reach(schema,"password",req.body.password);
    next();
  }
  catch(err){
    res.status(422).json({message:err.errors[0]});
  }
}

// Don't forget to add these to the `exports` object so they can be required in other modules

module.exports = {
  restricted,
  checkUsernameFree,
  checkPasswordLength,
  checkPayloadShape,
}