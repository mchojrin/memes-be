const mongoose = require("mongoose");

const Meme = mongoose.model(
  "Meme",
  new mongoose.Schema({
    path: String,
  })
);

module.exports = Meme;