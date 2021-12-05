require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const utils = require('./utils');
const db = require('./models');
const dbConfig = require('./db.config');
const { json } = require('body-parser');
const User = db.user;
const bcrypt = require('bcryptjs');
const fileUpload = require('express-fileupload');

const app = express();
const port = process.env.PORT || 4000;

db.mongoose
  .connect(`mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => {
    console.log("Successfully connected to MongoDB:" + JSON.stringify(dbConfig));
  })
  .catch(err => {
    console.error("Connection error", err);
    process.exit();
  });

// enable CORS
app.use(cors());
// parse application/json
app.use(bodyParser.json());
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

//middleware that checks if JWT token exists and verifies it if it does exist.
//In all future routes, this helps to know if the request is authenticated or not.
app.use(function (req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.headers['authorization'];
  if (!token) return next(); //if no token, continue

  token = token.replace('Bearer ', '');
  jwt.verify(token, process.env.JWT_SECRET, function (err, user) {
    if (err) {
      return res.status(401).json({
        error: true,
        message: "Invalid user."
      });
    } else {
      req.user = user; //set the user to req so other routes can use it
      next();
    }
  });
});

app.use(fileUpload({
}));

// request handlers
app.get('/', (req, res) => {
  if (!req.user) return res.status(401).json({ success: false, message: 'Invalid user to access it.' });
  res.send('Welcome to the Node.js Tutorial! - ' + req.user.name);
});

// validate the user credentials
app.post('/users/signin', function (req, res) {
  const user = req.body.username;
  const pwd = req.body.password;

  console.log('Login attempt ' + JSON.stringify(req.body));

  // return 400 status if username/password is not exist
  if (!user || !pwd) {
    return res.status(400).json({
      error: true,
      message: "Username and Password is required."
    });
  }

  console.log('Looking into the DB for a user ' + user);
  User.findOne({
    username: user
  }).exec(
    (err, user) => {
      if (err) {
        console.log('Error' + err);
        res.status(500).send({ message: err });
        return;
      }

      if (!user) {
        console.log('Not found');
        res.status(404).send({ message: "No such user!" });

        return;
      } else {
        console.log('User found, checking password "' + pwd + '" against "' + user.password + '"');
        bcrypt.compare(pwd, user.password, (err, isMatch) => {
          if (err) {
            console.log('Error checking password ' + err);

            return res.status(500).json({
              error: true,
              message: "Error checking password."
            });
          }

          if (!isMatch) {
            console.log('Passwords don\'t match');

            return res.status(401).json({
              error: true,
              message: "Username or password incorrect."
            });
          }

          console.log('Password ok, generating token');
          // generate token
          const token = utils.generateToken(user);
          // get basic user details
          const userObj = utils.getCleanUser(user);
          // return the token along with user details
          return res.json({ user: userObj, token });
        });
      }
    });
});


// validate the user credentials
app.post('/users/signup', function (req, res) {
  const user = req.body.username;
  const pwd = req.body.password;
  const name = req.body.name;

  console.log('Signup attempt ' + JSON.stringify(req.body));

  // return 400 status if username/password is not exist
  if (!user || !pwd || !name) {
    console.log('Incomplete request ' + JSON.stringify(req.body));

    return res.status(400).json({
      error: true,
      message: "Username, Password and name are required."
    });
  }

  console.log('Looking into the DB for a user ' + user);
  User.findOne({
    username: user
  }).exec(
    (err, user) => {
      if (err) {
        console.log('Error' + err);
        res.status(500).send({ message: err });
        return;
      }

      if (user) {
        console.log('User already in the db');
        res.status(400).send({ message: "Username is already in use!" });

        return;
      } else {
        console.log('User not found, creating');
        bcrypt.hash(req.body.password, 8, (err, hashedPassword) => {
          if (err) {
            console.log('Error hashing password: ' + err);
            return err;
          }

          // Display the hashed password
          console.log('Hashed password "' + hashedPassword + '"');
          const user = new User({
            username: req.body.username,
            name: req.body.name,
            password: hashedPassword
          });

          console.log('Saving user ' + JSON.stringify(user));

          user.save((err, user) => {
            if (err) {
              console.log('Error saving user: ' + err);
              res.status(500).send({ message: err });
              return;
            }

            console.log('User saved');
          });

          // generate token
          const token = utils.generateToken(user);
          // get basic user details
          const userObj = utils.getCleanUser(user);
          // return the token along with user details
          return res.json({ user: userObj, token });
        });
      }
    });
});

app.post('/memes/upload', function (req, res) {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files were uploaded.');
  }

  let uploadedFile = req.files.File;
  console.log('Trying to upload a file: ' + JSON.stringify(uploadedFile.name));

  uploadPath = __dirname + '/uploads/' + uploadedFile.name;

  console.log('Moving file to uploads directory');
  uploadedFile.mv(uploadPath, function(err) {
    if (err) {
      console.log('Upload failed: ' + err);
      return res.status(500).send(err);
    }

    console.log('Upload succesful!');
    res.send('File uploaded!');
  });
});

// verify the token and return it if it's valid
app.get('/verifyToken', function (req, res) {
  // check header or url parameters or post parameters for token
  var token = req.query.token;
  if (!token) {
    return res.status(400).json({
      error: true,
      message: "Token is required."
    });
  }
  // check token that was passed by decoding token using secret
  jwt.verify(token, process.env.JWT_SECRET, function (err, user) {
    if (err) return res.status(401).json({
      error: true,
      message: "Invalid token."
    });

    // return 401 status if the userId does not match.
    if (user.userId !== userData.userId) {
      return res.status(401).json({
        error: true,
        message: "Invalid user."
      });
    }
    // get basic user details
    var userObj = utils.getCleanUser(userData);
    return res.json({ user: userObj, token });
  });
});

app.listen(port, () => {
  console.log('Server started on: ' + port);
});