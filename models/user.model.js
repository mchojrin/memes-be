const mongoose = require("mongoose");

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    username: String,
    password: String,
    name: String,
    memes: Array
  })
);

module.exports = User;