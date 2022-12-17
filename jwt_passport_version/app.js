const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const fakeLocal = require('./fakeLocal.json');
const bodyParser = require('body-parser');
const path = require('path');
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const users = require('../users.json');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: false }));

passport.use(
  'login',
  new localStrategy(async (username, password, done) => {
    //failed authentication
    /*   return done(null, false, { message: 'User not found' }); */

    //successfull authentication
    return done(
      null,
      { username: 'bob', id: '123' },
      { message: 'Congrats! You are logged in!' }
    );
  })
);

passport.use(
  'signup',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      try {
        if (passport.length <= 4 || !email) {
          done(null, false, { message: 'Credentials invalid' });
        } else {
          const hashedPass = await bcrypt.hash(password, 10);
          let newUser = { email, password: hashedPass, id: uuidv4() };
          users.push(newUser);

          await fs.writeFile('users.json', JSON.stringify(users), (err) => {
            if (err) return done(err);
            console.log('updated the fake database');
          });

          return done(null, newUser, { message: 'Signed up successfully!' });
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

app.get('/', (req, res) => {
  res.send('nothing to see here.');
});

app.get('/secretroute', async (req, res) => {
  res.send('secretroute');
});

app.get('/logout', async (req, res) => {
  res.send('logout');
});

app.get('/login', async (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res, next) => {
  passport.authenticate('login', async (err, user, info) => {
    if (err) {
      return next(err.message);
    }

    if (!user) {
      res.redirect(`/failed?message=${info.message}`);
    } else {
      res.redirect(`/success?message=${info.message}`);
    }
  })(req, res, next);
});

app.get('/signup', async (req, res) => {
  res.render('signup');
});

app.post('/signup', async (req, res, next) => {
  passport.authenticate('signup', async (err, user, info) => {
    if (err) {
      return next(err.message);
    }

    if (!user) {
      res.redirect(`/failed?message=${info.message}`);
    }

    const body = { _id: user.id, email: user.email };

    const token = jwt.sign({ user: body }, 'TOP_SECRET');

    await fs.writeFile(
      'fakeLocal.json',
      JSON.stringify({ Authorization: `Bearer ${token}` }),
      (err) => {
        if (err) throw err;
      }
    );

    res.redirect(`success?message=${info.message}`);
  })(req, res, next);
});

app.get('/failed', async (req, res) => {
  res.send(`failed ${req.query.message}`);
});

app.get('/success', async (req, res) => {
  res.send(`success ${req.query.message}`);
});

app.listen(3000, () => {
  console.log('server listening on port 3000');
});
