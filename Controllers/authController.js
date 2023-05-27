// authController.js

const login = (req, res, next) => {
    passport.authenticate("local", {
      successRedirect: "/",
      failureRedirect: "/api/login",
      failureFlash: true
    })(req, res, next);
  };
  
  const signup = async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      users.push({
        id: Date.now().toString(),
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
      });
      console.log(users);
      res.redirect("/api/login");
    } catch (e) {
      console.log(e);
      res.redirect("/api/signup");
    }
  };
  
  module.exports = { login, signup };
  