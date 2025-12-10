const mongoose = require('mongoose'); 

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },

    email: { 
        type: String, 
        required: true, 
        unique: true 
    },

    password: { 
        type: String, 
        required: true 
    },

    gender: { 
        type: String, 
        enum: ['male', 'female'], 
        required: true 
    },

    otp: { 
        type: String 
    },

    otpExpires: { 
        type: Date 
    },

    isVerified: { 
        type: Boolean, 
        default: false
    },
    resetOtp:        { type: String },
  resetOtpExpires: { type: Date },

  // 🔽 Delete account ke liye
  deleteOtp:        { type: String },
  deleteOtpExpires: { type: Date },

    trustedDevices: [
    {
      deviceId: String,
      userAgent: String,
      addedAt: Date
    }
  ],

  loginOtp: String,
  loginOtpExpires: Date
});



module.exports = mongoose.model('User', userSchema);