// config/db.js
require('dotenv').config();
const mongoose = require('mongoose');

mongoose.set('strictQuery', false); // optional, removes warning

const MONGO_URI = process.env.MONGO_URL || process.env.MONGO_URI || process.env.MONGO_URI_STRING || 'mongodb://0.0.0.0/men';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("✅ Connected to Database");
  })
  .catch((err) => {
    console.error("❌ Error in Database", err);
  });

mongoose.connection.on('connected', () => console.log('Mongoose connection state: connected'));
mongoose.connection.on('error', err => console.error('Mongoose connection error:', err));
mongoose.connection.on('disconnected', () => console.log('Mongoose disconnected'));

module.exports = mongoose;