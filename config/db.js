// config/db.js
const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://0.0.0.0:27017/men';

const options = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 10000
};

mongoose.connect(MONGO_URI, options)
  .then(() => {
    console.log("✅ Connected to Database");
  })
  .catch((err) => {
    console.error("❌ Error in Database", err);
  });

module.exports = mongoose;