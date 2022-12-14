require("dotenv").config();
require("./config/database").connect();

const bcrypt = require("bcryptjs");
const auth = require("./middleware/auth");
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Logic goes here

// importing user context
const User = require("./model/user");

// Register
app.post("/register", async (req, res) => {
  // Our register logic starts here
  try {
    // Get user input
    const { fullName, email, password } = req.body;

    // Validate user input
    if (!(email && password && fullName)) {
      res.status(400).send("All User input is required");
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ email });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      fullName,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, email, fullName },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    // save user token
    user.token = token;

    // return new user
    // res.status(201).json(user); //Reply with all user details
    res.status(201).json(user.token); //Reply with user token
  } catch (err) {
    console.log(err);
  }
  // Our register logic ends here
});

// Login
app.post("/login", async (req, res) => {
  // Our login logic starts here
  try {
    // Get user input
    const { email, password } = req.body;

    // Validate user input
    if (!(email && password)) {
      res.status(400).send("All input is required");
    }
    // Validate if user exist in our database
    const user = await User.findOne({ email: email.toLowerCase() });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email, fullName: user.fullName },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // save user token
      user.token = token;

      // user
      // res.status(200).json(user); //Reply with all user details
      res.status(200).json(user.token); //Reply with user token
    }
    res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
  // Our login logic ends here
});

//Users
app.post("/users", auth, async (req, res) => {
  // res.status(200).send("Welcome ???? ");
  const users = await User.find();
  res.status(200).json(users);
});

//db.collection.findOne()
//db.collection.findOneAndReplace()
//db.collection.findOneAndDelete()
//db.collection.find()
module.exports = app;
