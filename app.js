const express = require('express');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');

const dbConnection = require('./config/db'); // अगर ये connect कर रहा है तो ठीक है
const userModel = require('./User');

require('dotenv').config({ path: '/home/shiv-kumar/Desktop/models/.env' });

const app = express();

mongoose.set('strictQuery',false);


// session setup
const MongoStore = require("connect-mongo");

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,            // हर request पर timeout reset हो जाएगा
  cookie: {
    httpOnly: true,
    secure: false,          // production + https पर true कर दे
    maxAge: 1 * 60 * 1000   // 1 minute (idle timeout)
  }
}));

// अगर behind proxy (Heroku/Render) तो true रहे
app.set('trust proxy',1);

app.use(helmet());
app.use(morgan('dev'));

// rate limiter (default)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1500, // 15 minutes
  max: 1000,
  message: "Too many requests, try again later."
});
app.use(limiter);

app.use(cookieParser());

// helper: client IP
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  req.clientIP = ip;
  console.log("Client IP:", ip);
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// static files
app.use(express.static("public", {
  etag: false,
  lastModified: false,
  setHeaders: (res, path) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  }
}));

app.set("view engine", 'ejs');

// global cache headers (to avoid back-button loop)
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// message middleware: session.message -> res.locals.message (one-time)
app.use((req, res, next) => {
  if (req.session && req.session.message) {
    res.locals.message = req.session.message;
    delete req.session.message;
  } else {
    res.locals.message = null;
  }
  next();
});

// debug logs
app.use((req, res, next) => {
  console.log('Session:', req.session);
  console.log(`${req.method} ${req.url}`);
  next();
});

// root -> login
app.get('/', (req, res) => {
  return res.redirect('/login');
});

// safe isAuthenticated
function isAuthenticated(req, res, next) {
  if (req && req.session && req.session.user) return next();
  if (req && req.session) {
    // remove stale user
    req.session.user = undefined;
  }
  return res.redirect('/login');
}

// ----------------- Routes -----------------

app.get('/login', (req, res) => {
  // if already logged in -> home
  if (req.session && req.session.user) return res.redirect('/home');
  res.render('index', { message: res.locals.message || null });
});

// DEBUG route - remove after testing
app.get('/__debug_users', async (req, res) => {
  try {
    const docs = await userModel.find().limit(20).lean();
    console.log('DEBUG /__debug_users count:', docs.length);
    res.json({ count: docs.length, docs });
  } catch (err) {
    console.error('DEBUG fetch users error', err);
    res.status(500).json({ error: String(err) });
  }
});

app.get('/register', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/home');
  res.render('register', { message: res.locals.message || null });
});

app.get('/Forgotpassword', (req, res) => {
  if (req.session && req.session.user) return res.redirect('/home');
  res.render('Forgotpassword', { error: null, message: res.locals.message || null });
});

app.get('/',(req, res) =>{
    res.render('index')
});

app.get('/Contact',(req, res) =>{
    res.render('contact')
});
app.get('/service',(req, res) =>{
    res.render('contact')
});

app.get('/delete-user', isAuthenticated, (req, res) => {
  res.render('DeleteUser', { error: null, message: res.locals.message || null });
});

app.get('/home', isAuthenticated, (req, res) => {
  console.log(req.session);
  res.render('home', { user: req.session.user, message: res.locals.message || null });
});

app.get('/protected-route', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).redirect('/login');
  }
  const email = req.session.user.email;
  res.render('home', { email });
});

// ----------------- Register -----------------
app.post('/register', async (req, res) => {
  try {
    // sanitize + normalize
    let { username, email, password, dob, gender } = req.body || {};
    username = (username || '').trim();
    email = (email || '').trim().toLowerCase();
    password = password || '';

    console.log('Register attempt:', { username, email, dob, gender });

    // validation
    if (!username || !email || !password) {
      req.session.message = 'सभी fields भरें';
      return res.redirect('/register');
    }
    if (password.length < 8) {
      req.session.message = 'पासवर्ड कम से कम 8 अक्षरों का होना चाहिए';
      return res.redirect('/register');
    }

    // check existing
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      // अगर ईमेल पहले से है -> यूजर को लॉगिन पर भेजो
      req.session.message = 'यह ईमेल पहले से रजिस्टर्ड है — कृपया लॉगिन करें';
      return res.redirect('/login');
    }

    // hash and create
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await userModel.create({
      username,
      email,
      password: hashedPassword,
      dob,
      gender,
      isVerified: true
    });

    console.log('User created:', newUser._id);

    // set session and redirect
    req.session.user = {
      id: newUser._id,
      username: newUser.username,
      email: newUser.email
    };

    // save session (optional, but good for safety) then redirect
    req.session.save(err => {
      if (err) {
        console.error('Session save error after register:', err);
        // phir bhi home bhej de
        return res.redirect('/home');
      }
      return res.redirect('/home');
    });

  } catch (error) {
    console.error('Register error:', error);

    // duplicate key from mongoose (race)
    if (error && error.code === 11000) {
      req.session.message = 'ईमेल पहले से मौजूद है';
      return res.redirect('/login');
    }

    req.session.message = 'रजिस्ट्रेशन असफल, कृपया फिर से प्रयास करें';
    return res.redirect('/register');
  }
});

// ----------------- Forgot password (simple update) -----------------
app.post('/Forgotpassword', async (req, res) => {
  try {
    const { email, username, newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      req.session.message = 'नया पासवर्ड कम से कम 8 अक्षरों का होना चाहिए';
      return res.redirect('/Forgotpassword');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const user = await userModel.findOneAndUpdate(
      { email, username },
      { password: hashedPassword },
      { new: true }
    );

    if (!user) {
      req.session.message = 'यूजर नहीं मिला';
      return res.redirect('/Forgotpassword');
    }

    req.session.message = 'पासवर्ड बदल दिया गया है, कृपया लॉगिन करें';
    return res.redirect('/login');
  } catch (error) {
    console.error('Forgotpassword error:', error);
    req.session.message = 'पासवर्ड रीसेट असफल';
    return res.redirect('/Forgotpassword');
  }
});

// ----------------- Delete user -----------------
app.post('/delete-user', isAuthenticated, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      req.session.message = 'User नहीं मिला';
      return res.redirect('/home');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      req.session.message = 'गलत पासवर्ड';
      return res.redirect('/home');
    }

    await userModel.findOneAndDelete({ _id: user._id });

    req.session.destroy(err => {
      if (err) console.error('Session destroy error:', err);
      return res.redirect('/register');
    });

  } catch (error) {
    console.error('Delete error:', error);
    req.session.message = 'Account delete करने में त्रुटि';
    return res.redirect('/home');
  }
});

// ----------------- Login -----------------
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      req.session.message = 'ईमेल और पासवर्ड दोनों भरें';
      return res.redirect('/login');
    }

    const user = await userModel.findOne({ email });
    if (!user) {
      // email not registered -> redirect to register
      req.session.message = 'यह ईमेल रजिस्टर्ड नहीं है — कृपया पहले रजिस्टर करें';
      return res.redirect('/register');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      req.session.message = 'Incorrect Password';
      return res.redirect('/login');
    }

    // success
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email
    };

    // save then redirect
    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        req.session.message = 'Session save failed';
        return res.redirect('/login');
      }
      console.log('✅ Session saved:', req.session.user);
      return res.redirect('/home');
    });

  } catch (error) {
    console.error('Login error:', error);
    req.session.message = 'Login failed, try again';
    return res.redirect('/login');
  }
});

// ----------------- Logout -----------------
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Logout destroy error:', err);
    return res.redirect('/login');
  });
});

// ----------------- Error handler -----------------
app.use((err, req, res, next) => {
  console.error(err.stack);
  return res.status(500).send('कुछ गलत हो गया!');
});

// start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server Running On http://localhost:${PORT}`);
});