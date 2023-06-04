const express = require("express");
const session = require("express-session");
const hbs = require("express-handlebars");
//const mongoose = require('mongoose');
const { Sequelize, DataTypes } = require("sequelize");
const passport = require("passport");
const localStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const app = express();

/**Connexion à la bdd */

const sequelize = new Sequelize("rules_db", "moses", "moses", {
  host: "localhost",
  dialect: "postgres",
});

// Vérifiez la connexion à la base de données
sequelize
  .authenticate()
  .then(() => {
    console.log("Connexion à la base de données réussie.");
  })
  .catch((err) => {
    console.error("Impossible de se connecter à la base de données:", err);
  });

//Model definitione

const User = sequelize.define("User", {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

const Role = sequelize.define("Role", {
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

User.belongsTo(Role);

User.sync({ force: true })
  .then((data) => {
    console.log("La table User cree avec succes");
  })
  .catch((err) => {
    console.log("Erreur survenue lors de la creation de la table user");
  });

Role.sync({ force: true })
  .then((data) => {
    console.log("La table role a ete cree");
    Role.create({ name: "admin" });
  })
  .catch((err) => {
    console.log("Erreur survenue lors de la creation de la table role");
  });

// Middleware

app.engine("hbs", hbs({ extname: ".hbs" }));
app.set("view engine", "hbs");
app.use(express.static(__dirname + "/public"));
app.use(
  session({
    secret: "verygoodsecret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findByPk(id, { include: Role })
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err, null);
    });
});

passport.use(
  new localStrategy(function (username, password, done) {
    User.findOne({ where: { username: username } })
      .then((user) => {
        if (!user)
          return done(null, false, { message: "Mot de passe incorrect." });

        bcrypt.compare(password, user.dataValues.password, function (err, res) {
          if (err) return done(err);
          if (res === false)
            return done(null, false, { message: "Mot de passe incorrect." });

          return done(null, user);
        });
      })
      .catch((err) => {
        return done(err);
      });
  })
);

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

function isLoggedOut(req, res, next) {
  if (!req.isAuthenticated()) return next();
  res.redirect("/");
}

function isAdmin(req, res, next) {
  if (req.user && req.user.Role && req.user.Role.name === "admin") {
    next();
  } else {
    res.redirect("/");
  }
}

// ROUTES

// app.get("/admin", isAdmin, (req, res) => {
//   //code pour la page d'administration
// });

app.get("/", isLoggedIn, isAdmin, (req, res) => {
  res.render("index", { title: "Home Admin" });
});

app.get("/about", (req, res) => {
  res.render("index", { title: "About" });
});

app.get("/login", isLoggedOut, (req, res) => {
  const response = {
    title: "Login",
    error: req.query.error,
  };

  res.render("login", response);
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login?error=true",
  })
);

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

// Setup our admin user

app.get("/setup", async (req, res) => {
  const exists = await User.findOne({ where: { username: "admin" } });

  if (exists) {
    res.redirect("/login");
    return;
  }

  bcrypt.genSalt(10, function (err, salt) {
    if (err) {
      console.error(err);
      res.redirect("/login");
      return;
    }
    bcrypt.hash("pass", salt, function (err, hash) {
      if (err) {
        console.error(err);
        res.redirect("/login");
        return;
      }

      User.create({
        username: "admin",
        password: hash,
        RoleId: 1,
      })
        .then(() => {
          console.log("Admin user created successfully.");
          res.redirect("/login");
        })
        .catch((err) => {
          console.error("Failed to create admin user:", err);
          res.redirect("/login");
        });
    });
  });
});

app.listen(3000, () => {
  console.log("Lancee au numero de port 3000");
});
