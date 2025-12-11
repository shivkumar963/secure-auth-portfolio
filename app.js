const express=require('express');

const session = require('express-session');

const mongoose=require('mongoose');

const bcrypt=require('bcrypt');

const cookieParser = require('cookie-parser');

const helmet = require('helmet');

const morgan=require('morgan');

const rateLimit = require('express-rate-limit');

const dotenv=require('dotenv');

const dbConnection=require('./config/db');

const userModel = require('./User');


require('dotenv').config();

const app=express();

app.use(helmet());

app.use(morgan('dev'));

// ---------------- safer trust proxy + rate limit ----------------
/*
 If app runs behind one proxy (eg. Render, Heroku), set trust proxy = 1
 Do NOT set it boolean true (express-rate-limit will complain).
*/
app.set('trust proxy', 1); // number 1 is safe for single-proxy hosting

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                 // limit each IP to 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  // keyGenerator: use x-forwarded-for first then socket ip (safer)
  keyGenerator: (req) => {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.ip || req.socket.remoteAddress || 'unknown';
  },
  skipFailedRequests: true, // optional: don't count failed responses
  message: "Too many requests from your IP, try again later."
});

app.use(limiter);

app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET, 
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 1000 * 60 * 1
  }
}));


app.use(express.urlencoded({extended: true}));

app.use(express.json());

app.use(express.static("public", {
  etag: false, 
  lastModified: false, 
  setHeaders: (res, path) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

  }
}));



app.set("view engine", 'ejs');

app.get('/login', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  console.log(req.session); 
  res.render('index', { message: null });  // ✅ yahan message bhej
});

app.use((req, res, next) => {
  console.log('Session:', req.session);
  next();
});


app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

app.get('/protected-route', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).redirect('/login');
  }

  const email = req.session.user.email;
  res.render('home', { email });  
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

app.get('/delete-user',(req, res) =>{
    res.render('DeleteUser')
});

app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});



 app.get('/register', (req, res)=>{
        res.render('register')
    });

    app.get('/Forgotpassword', (req, res) =>{
        res.render('Forgotpassword')
    });


app.get('/home', isAuthenticated, (req, res) => {
  console.log(req.session); 
  res.render('home', { user: req.session.user });
});



app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('कुछ गलत हो गया!');
});




function isAuthenticated(req, res, next ){
    if(req.session.user){
        return next();}
    res.redirect('/login');
}



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

        const newUser = await userModel.create({
            username,
            email,
            password: hashedPassword,
            dob,
            gender,
        });

        req.session.user = {
            id: newUser._id,
            username: newUser.username,
            email: newUser.email
        };

        res.redirect('/home');

    } catch (error) {
        console.error(error);
        res.status(500).render('register', { 
            message: 'रजिस्ट्रेशन असफल, कृपया फिर से प्रयास करें' 
        });
    }
});



     
app.post('/Forgotpassword', async (req, res) => {
    try {
        const {email, username, newPassword} = req.body;

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const user = await userModel.findOneAndUpdate(
            { email,username},
            { password: hashedPassword }
        );

        if (!user) {
            return res.status(404).render('Forgotpassword', {
                error: 'यूजर नहीं मिला'
            });
        }

        res.redirect('/login');
    } catch (error) {
        console.error(error);
        res.status(500).render('Forgotpassword', {
            error: 'पासवर्ड रीसेट असफल'
        });
    }
});



app.post('/delete-user', isAuthenticated, async (req, res) => {

  const {email,password} = req.body;

  const user = await userModel.findOne({email});

  if(!user){
return res.status(404).send("User Not Found");

  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {return res.status(401).send("Incorrect password");}

  await userModel.findOneAndDelete({email:user.email});

  req.session.destroy();

  res.redirect('/register');

});


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
  req.session.destroy();
  res.redirect('/login');
});


const PORT=process.env.PORT||3000;

app.listen(PORT,()=>{
console.log(`Server Running On http://localhost:${PORT}`);

});