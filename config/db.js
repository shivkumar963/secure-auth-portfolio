const mongoose = require('mongoose');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://0.0.0.0/men';

const connection = mongoose.connect(MONGO_URI)
  .then(() => {
    console.log("✅ Connected to Database");
  })
  .catch((err) => {
    console.error("❌ Error in Database", err);
  });

module.exports = connection;
