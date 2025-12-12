const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  dob: String,
  gender: String,
  isVerified: { type: Boolean, default: false },
  // other otp fields removed as you asked
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);