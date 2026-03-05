const mongoose = require("mongoose");

const logSchema = new mongoose.Schema({
  userId: String,
  email: String,
  result: Object,
}, { timestamps: true });

module.exports = mongoose.model("EmailLog", logSchema);