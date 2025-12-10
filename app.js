const express = require('express');
const session = require('express-session');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');

const dbConnection = require('./config/db');
const userModel = require('./User');

require('dotenv').config();

const app = express();



// ✅ Debug env load
console.log("EMAIL USER:", process.env.EMAIL_USER);
console.log("EMAIL PASS:", process.env.EMAIL_PASS ? "✅ loaded" : "❌ missing");

// ---------------- Security & basic middlewares ----------------

app.use(helmet());
app.use(morgan('dev'));

// ✅ Rate limit (global)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many attempts. Try later."
});
app.use(limiter);

app.use(cookieParser());

// ✅ Device ID middleware (naya device OTP ke liye)
app.use((req, res, next) => {
  let deviceId = req.cookies.deviceId;

  if (!deviceId) {
    deviceId = crypto.randomBytes(16).toString('hex');
    res.cookie('deviceId', deviceId, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365
    });
  }

  req.deviceId = deviceId;
  req.userAgent = req.headers['user-agent'] || 'unknown';

  next();
});

// ✅ Session
const SESSION_IDLE_TIME = 1000 * 60 * 2; // 5 minute (jitna chaahe utna kar sakta hai)

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,              // ✅ har request pe time reset (inactivity timeout)
  cookie: {
    secure: false,            // https hoga to true kar dena
    httpOnly: true,
    maxAge: SESSION_IDLE_TIME // ✅ session 5 minute idle ke baad expire
  }
}));

// ✅ Client IP logging (optional)
app.use((req, res, next) => {
  const ip =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.socket.remoteAddress;

  req.clientIP = ip;
  console.log("Client IP:", ip);
  next();
});

// ✅ Global no-cache (BACK button loop avoid)
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Static files
app.use(express.static("public", {
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  }
}));

app.set("view engine", 'ejs');

// Optional debug logs
app.use((req, res, next) => {
  console.log('Session:', req.session);
  next();
});

app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// ---------------- Nodemailer setup ----------------

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendOTPEmail(email, otp) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for Verification',
    html: `
      <h2>OTP Verification</h2>
      <p>Your OTP is:</p>
      <h1>${otp}</h1>
      <p>OTP valid for 10 minutes.</p>
    `
  };

  await transporter.sendMail(mailOptions);
}

// ---------------- Logger (internal use only) ----------------

const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

// ---------------- Helper functions ----------------

function isAuthenticated(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

console.log("Test OTP:", generateOTP());

// ---------------- Routes: GET pages ----------------

// ✅ Login page: agar already login hai to home bhej
app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/home');
  }
  res.render('index', { message: null });
});

app.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/home');
  }
  res.render('register');
});

app.get('/Forgotpassword', (req, res) => {
  if (req.session.user) {
    return res.redirect('/home');
  }
  res.render('Forgotpassword', { error: null, message: null });
});

app.get('/delete-user', isAuthenticated, (req, res) => {
  res.render('DeleteUser', { error: null, message: null });
});

app.get('/contact', isAuthenticated, (req, res) => {
  res.render('contact', { error: null, message: null });
});

app.get('/home', isAuthenticated, (req, res) => {
  console.log(req.session);
  res.render('home', { user: req.session.user });
});

// ✅ Register OTP verify page
app.get('/otp-verify', (req, res) => {
  if (req.session.user) {
    // Already logged in, OTP page ki zarurat nahi
    return res.redirect('/home');
  }

  const { email } = req.query;
  if (!email) {
    return res.redirect('/register');
  }

  res.render('otp', { email, message: null });
});

// ✅ Login OTP page (new device)
app.get('/login-otp', (req, res) => {
  if (!req.session.pendingLoginUserId) {
    return res.redirect('/login');
  }
  res.render('login-otp', { message: null });
});

// Optional protected test route
app.get('/protected-route', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).redirect('/login');
  }

  const email = req.session.user.email;
  res.render('home', { email });
});

// ---------------- Routes: OTP verify (Register) ----------------

app.post('/otp-verify', async (req, res) => {
  try {
    let { email, otp } = req.body;

    email = String(email || '').trim();
    otp = String(otp || '').trim();

    console.log("🔍 OTP verify request:", { email, otp });

    const user = await userModel.findOne({ email });

    if (!user) {
      console.log("❌ User not found for email:", email);
      return res.render('otp', {
        email,
        message: 'User nahi mila'
      });
    }

    const storedOtp = user.otp ? String(user.otp).trim() : null;
    console.log("📦 Stored OTP:", storedOtp);

    if (!storedOtp) {
      return res.render('otp', {
        email,
        message: 'OTP generate nahi mila, dubara register karein'
      });
    }

    if (otp !== storedOtp) {
      console.log("❌ OTP mismatch:", { inputOtp: otp, storedOtp });
      return res.render('otp', {
        email,
        message: 'Galat OTP'
      });
    }

    if (user.otpExpires && user.otpExpires < Date.now()) {
      console.log("⏰ OTP expired for", email);
      return res.render('otp', {
        email,
        message: 'OTP expire ho chuka hai'
      });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email
    };

    console.log("✅ OTP verified, session user:", req.session.user);

    return res.redirect('/home');

  } catch (err) {
    console.error('OTP verify error:', err);
    return res.render('otp', {
      email: req.body.email,
      message: 'OTP verify karte waqt error aaya'
    });
  }
});

// ---------------- Routes: Login OTP (new device verify) ----------------

app.post('/login-otp', async (req, res) => {
  try {
    const { otp } = req.body;
    const pendingUserId = req.session.pendingLoginUserId;

    if (!pendingUserId) {
      return res.redirect('/login');
    }

    const user = await userModel.findById(pendingUserId);
    if (!user) {
      return res.redirect('/login');
    }

    if (!user.loginOtp || !user.loginOtpExpires) {
      return res.render('login-otp', { message: 'OTP generate nahi mila' });
    }

    const now = Date.now();
    if (user.loginOtp !== String(otp).trim()) {
      return res.render('login-otp', { message: 'Galat OTP' });
    }

    if (user.loginOtpExpires < now) {
      return res.render('login-otp', { message: 'OTP expire ho chuka hai' });
    }

    // ✅ Naya device verified:
    user.trustedDevices = user.trustedDevices || [];
    user.trustedDevices.push({
      deviceId: req.deviceId,
      userAgent: req.userAgent,
      addedAt: new Date()
    });

    // Login OTP clear kar de
    user.loginOtp = undefined;
    user.loginOtpExpires = undefined;
    await user.save();

    // Pending login hataye
    req.session.pendingLoginUserId = undefined;

    // Ab actual login complete kare
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email
    };

    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).send('Internal Server Error');
      }

      console.log("✅ Login OTP verified, device trusted:", req.deviceId);
      res.redirect('/home');
    });

  } catch (err) {
    console.error("Login OTP verify error:", err);
    res.render('login-otp', { message: 'Login OTP verify karte waqt error' });
  }
});

// ---------------- Routes: Register ----------------

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, dob, gender } = req.body;

    if (!username || !email || !password || password.length < 8) {
      return res.status(400).render('register', {
        message: 'पासवर्ड कम से कम 8 अक्षरों का होना चाहिए और सभी fields भरें'
      });
    }

    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(400).render('register', {
        message: 'ईमेल पहले से उपयोग में है'
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const otp = generateOTP();
    console.log("Register OTP for", email, ":", otp);

    try {
      await sendOTPEmail(email, otp);
    } catch (mailErr) {
      console.error("Mail send error:", mailErr);
      return res.status(500).render('register', {
        message: 'OTP email bhejne me dikkat aayi, baad me try karein'
      });
    }

    await userModel.create({
      username,
      email,
      password: hashedPassword,
      dob,
      gender,
      otp: otp,
      otpExpires: Date.now() + 10 * 60 * 1000,
      isVerified: false
    });

    return res.redirect(`/otp-verify?email=${email}`);

  } catch (error) {
    console.error(error);
    res.status(500).render('register', {
      message: 'रजिस्ट्रेशन असफल, कृपया फिर से प्रयास करें'
    });
  }
});

// ---------------- Routes: Forgot Password + OTP ----------------

app.post('/Forgotpassword', async (req, res) => {
  try {
    const { email, username } = req.body;

    const user = await userModel.findOne({ email, username });
    if (!user) {
      return res.status(404).render('Forgotpassword', {
        error: 'यूजर नहीं मिला',
        message: null
      });
    }

    const otp = generateOTP();
    user.resetOtp = otp;
    user.resetOtpExpires = Date.now() + 10 * 60 * 1000;

    await user.save();

    console.log("🔐 Reset OTP for", email, ":", otp);
    await sendOTPEmail(email, otp);

    return res.render('ForgotpasswordOtp', {
      email,
      username,
      error: null,
      message: 'OTP आपके ईमेल पर भेज दिया गया है'
    });

  } catch (error) {
    console.error(error);
    res.status(500).render('Forgotpassword', {
      error: 'OTP भेजने में गलती हुई, बाद में कोशिश करें',
      message: null
    });
  }
});

app.post('/Forgotpassword/verify', async (req, res) => {
  try {
    const { email, username, otp, newPassword } = req.body;

    const user = await userModel.findOne({ email, username });
    if (!user) {
      return res.status(404).render('ForgotpasswordOtp', {
        email,
        username,
        error: 'यूजर नहीं मिला',
        message: null
      });
    }

    if (!user.resetOtp || !user.resetOtpExpires) {
      return res.render('ForgotpasswordOtp', {
        email,
        username,
        error: 'OTP सेट नहीं मिला, फिर से Forgot Password करें',
        message: null
      });
    }

    if (String(user.resetOtp).trim() !== String(otp).trim()) {
      return res.render('ForgotpasswordOtp', {
        email,
        username,
        error: 'गलत OTP',
        message: null
      });
    }

    if (user.resetOtpExpires < Date.now()) {
      return res.render('ForgotpasswordOtp', {
        email,
        username,
        error: 'OTP एक्सपायर हो चुका है',
        message: null
      });
    }

    if (!newPassword || newPassword.length < 8) {
      return res.render('ForgotpasswordOtp', {
        email,
        username,
        error: 'नया पासवर्ड कम से कम 8 अक्षरों का होना चाहिए',
        message: null
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    user.resetOtp = undefined;
    user.resetOtpExpires = undefined;

    await user.save();

    return res.redirect('/login');

  } catch (error) {
    console.error(error);
    res.status(500).render('ForgotpasswordOtp', {
      email: req.body.email,
      username: req.body.username,
      error: 'पासवर्ड रीसेट असफल',
      message: null
    });
  }
});

// ---------------- Routes: Delete User + OTP ----------------

app.post('/delete-user', isAuthenticated, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).render('DeleteUser', {
        error: 'User नहीं मिला',
        message: null
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).render('DeleteUser', {
        error: 'गलत पासवर्ड',
        message: null
      });
    }

    const otp = generateOTP();
    user.deleteOtp = otp;
    user.deleteOtpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    console.log("🗑 Delete OTP for", email, ":", otp);
    await sendOTPEmail(email, otp);

    return res.render('DeleteUserOtp', {
      email,
      error: null,
      message: 'Account delete करने के लिए OTP आपके ईमेल पर भेज दिया गया है'
    });

  } catch (error) {
    console.error(error);
    res.status(500).render('DeleteUser', {
      error: 'कुछ गलती हुई, बाद में कोशिश करें',
      message: null
    });
  }
});

app.post('/delete-user/otp', isAuthenticated, async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).render('DeleteUserOtp', {
        email,
        error: 'User नहीं मिला',
        message: null
      });
    }

    if (!user.deleteOtp || !user.deleteOtpExpires) {
      return res.render('DeleteUserOtp', {
        email,
        error: 'OTP सेट नहीं मिला, फिर से delete form submit करें',
        message: null
      });
    }

    if (String(user.deleteOtp).trim() !== String(otp).trim()) {
      return res.render('DeleteUserOtp', {
        email,
        error: 'गलत OTP',
        message: null
      });
    }

    if (user.deleteOtpExpires < Date.now()) {
      return res.render('DeleteUserOtp', {
        email,
        error: 'OTP expire हो चुका है',
        message: null
      });
    }

    await userModel.deleteOne({ _id: user._id });

    req.session.destroy(() => {
      res.redirect('/register');
    });

  } catch (error) {
    console.error(error);
    res.status(500).render('DeleteUserOtp', {
      email: req.body.email,
      error: 'Account delete करते समय error आया',
      message: null
    });
  }
});

// ---------------- Routes: Login + Logout ----------------

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(404).render('index', { message: "User Not Found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).render('index', { message: "Incorrect Password" });
    }

    if (!user.isVerified) {
      console.log("⚠️ Account not verified, redirect to register-OTP");
      return res.redirect(`/otp-verify?email=${email}`);
    }

    const deviceId = req.deviceId;
    const isTrusted = user.trustedDevices?.some(
      d => d.deviceId === deviceId
    );

    if (!isTrusted) {
      // Password sahi + isVerified true -> hamesha OTP

const loginOtp = generateOTP();
user.loginOtp = loginOtp;
user.loginOtpExpires = Date.now() + 10 * 60 * 1000;
await user.save();

console.log("📩 Login OTP for", email, ":", loginOtp);
await sendOTPEmail(email, loginOtp);

req.session.pendingLoginUserId = user._id;

return res.redirect('/login-otp');
    }

    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email
    };

    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.status(500).send('Internal Server Error');
      }

      console.log("✅ Session saved:", req.session.user);
      res.redirect('/home');
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Login Failed');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});



// ---------------- Global error handler ----------------

app.use((err, req, res, next) => {
  console.error(err.stack);
  logger.error(err.stack);
  res.status(500).send('कुछ गलत हो गया!');
});

// ---------------- Start server ----------------

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server Running On http://localhost:${PORT}`);
});