if (process.env.NODE_ENV !== "production") {
  require("dotenv").config()
}


// Importing Libraies that we installed using npm
const express = require("express")
const app = express()
const bcrypt = require("bcrypt") // Importing bcrypt package
const passport = require("passport")
const initializePassport = require("./passport-config")
const flash = require("express-flash")
const session = require("express-session")
const methodOverride = require("method-override")
const jwt = require('jsonwebtoken');

initializePassport(
  passport,
  email => users.find(user => user.email === email),
  id => users.find(user => user.id === id)
  )

const users = []

const Article = require('./models/articles.ejs');

app.use(express.urlencoded({extended: false}))
app.use(flash())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false, // We wont resave the session variable if nothing is changed
  saveUninitialized: false
}))
app.use(passport.initialize()) 
app.use(passport.session())
app.use(methodOverride("_method"))



// Configuring the register post functionality
app.post('/api/login', checkNotAuthenticated, passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/api/login',
  failureFlash: true,
}), (req, res) => {
  const user = { id: req.user.id, name: req.user.name, email: req.user.email };
  const token = jwt.sign(user, process.env.JWT_SECRET);
  res.json({ token });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}


// Configuring the register post functionality
app.post("/api/signup", checkNotAuthenticated, async (req, res) => {

  try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10)
      users.push({
          id: Date.now().toString(), 
          name: req.body.name,
          email: req.body.email,
          password: hashedPassword,
      })
      console.log(users); // Display newly registered in the console
      res.redirect("/api/login")
      
  } catch (e) {
      console.log(e);
      res.redirect("/api/signup")
  }
})

app.post('/api/users/:userId/articles', authenticateToken, async (req, res) => {
  try {
    // Get the user ID from the request parameters
    const userId = req.params.userId;

    // Retrieve the article details from the request body
    const { title, content } = req.body;

    // Create a new article object
    const article = new Article({
      title,
      content,
      userId
    });

    // Save the article to the database
    await article.save();

    res.status(201).json({ message: 'Article created successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Routes
app.get('/', checkAuthenticated, (req, res) => {
  res.render("index.ejs", {name: req.user.name})
})

app.get('/api/login', checkNotAuthenticated, (req, res) => {
  res.render("login.ejs")
})

app.get('/api/signup', checkNotAuthenticated, (req, res) => {
  res.render("register.ejs")
})

app.get('/api/articles', authenticateToken, async (req, res) => {
  try {
    // Fetch all articles from the database
    const articles = await Article.find();

    res.json(articles);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete("/logout", (req, res) => {
  req.logout(req.user, err => {
      if (err) return next(err)
      res.redirect("/")
  })
})

app.put('/api/users/:userId', authenticateToken, async (req, res) => {
  try {
    // Get the user ID from the request parameters
    const userId = req.params.userId;

    // Retrieve the user details from the request body
    const { name, age } = req.body;

    // Find the user in the database by ID
    const user = await User.findById(userId);

    // Update the user's name and age
    user.name = name;
    user.age = age;

    // Save the updated user to the database
    await user.save();

    res.json({ message: 'User profile updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

function checkAuthenticated(req, res, next){
  if(req.isAuthenticated()){
      return next()
  }
  res.redirect("/api/login")
}

function checkNotAuthenticated(req, res, next){
  if(req.isAuthenticated()){
      return res.redirect("/")
  }
  next()
}

app.listen(3000)