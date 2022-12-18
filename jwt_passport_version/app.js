const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const fakeLocal = require('./fakeLocal.json');
const bodyParser = require('body-parser');
const path = require('path');
const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const users = require('../users.json');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const secureRoutes = require('./secureRoutes');

const app = express();

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: false }));

app.use(passport.initialize());

app.use('/user', secureRoutes);

const getJwt = () => {
  console.log('get jwt');
  return fakeLocal.Authorization?.substring(7); // remove "Bearer" from the token.
};

passport.use(
  new JwtStrategy(
    {
      secretOrKey: 'TOP_SECRET',
      jwtFromRequest: getJwt,
    },
    async (token, done) => {
      console.log('in jwt strategy token: ' + token);

      // 00a: Doesn't even make it throught the getJwt function check. Prints "unauthorized"
      // 00b: Invalid token. Prints "unauthorized"

      // 01: Make sit into this function but gets an app error.
      // Simulate an app error:

      if (token?.user?.email == 'tokenerror') {
        let testError = new Error('Simulated error!');
        return done(testError, false);
      }

      // 02: Some other reason for the user to not exist. Pass "false" as user. Displays "unauthozited" and does not call the next function in the chain.
      if (token?.user?.email == 'emptytoken') {
        return done(null, false);
      }

      // 03: successfully decoded and validated user:
      // adds the req.user, req.login etc. properties to the req and calls the next function in the chain
      return done(null, token.user);
    }
  )
);

passport.use(
  'login',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      console.log('login named');

      // done(null, userObject, {message: "Optional success/fail message"});
      // done(err); // application error
      // done(null, false, {message: "Unauthorized login credentials!"}); User input error when second parameter is false

      try {
        if (email === 'apperror') {
          throw new Error('Oh no! The app crashed!');
        }

        const user = users.find((user) => user.email === email);

        if (!user) {
          return done(null, false, { message: 'user not found!' });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
          return done(null, false, { message: 'invalid credentials!' });
        }

        return done(null, user, { message: 'You are logged in!' });
      } catch (err) {
        return done(err);
      }
    }
  )
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

app.get(
  '/secureroute',
  passport.authenticate('jwt', { session: false }),
  async (req, res) => {
    // 1. Try visiting this route WITHOUT logging in. The authenticate("jwt") line will prevent you from ever getting here.
    //// You should get "unauthorized". In this case use a front end to route appropriately.
    // 2. Try visiting this route with an invalid jwt. So... login, manually alter the jwt, then visit secure route.
    //// you should get "unauthorized" here too. You would use the front end to route in this case.

    // 3. Try visiting this route when logged in with a working user.
    // req.user, req.isAuthenticated, login and logout should all work.

    console.log('------ beginning of /secureroute -----');
    console.log('req.isAuthenticated: ', req.isAuthenticated());
    console.log('req.user: ', req.user);
    console.log('req.login: ', req.login);
    console.log('req.logout: ', req.logout);

    res.send(`Welcome to the top secret place, ${req.user.email}`);
  }
);

app.get('/logout', async (req, res) => {
  await fs.writeFile(
    './jwt_passport_version/fakeLocal.json',
    JSON.stringify({ Authorization: '' }),
    (err) => {
      if (err) throw err;
    }
  );
  res.redirect('/login');
});

app.get('/login', async (req, res) => {
  res.render('login');
});

app.post(
  '/login',
  async (req, res, next) => {
    passport.authenticate('login', async (err, user, info) => {
      console.log('err: ', err);
      console.log('user: ', user);
      console.log('info: ', info);

      if (err) {
        return next(err.message);
        // return next error-message or error
      }

      if (!user) {
        res.redirect(`/failed?message=${info.message}`);
      } else {
        const body = { _id: user.id, email: user.email };
        const token = jwt.sign({ user: body }, 'TOP_SECRET');

        await fs.writeFile(
          './jwt_passport_version/fakeLocal.json',
          JSON.stringify({ Authorization: `Bearer ${token}` }),
          (err) => {
            if (err) throw err;
          }
        );

        res.redirect(`/success?message=${info.message}`);
      }
    })(req, res, next);
  },
  (req, res, next) => {
    res.send('I was called after the authentication call!'); // only if function didn't return already
  }
);

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
      './jwt_passport_version/fakeLocal.json',
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
