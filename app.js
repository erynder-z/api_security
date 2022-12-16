const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const fakeLocal = require('./fakeLocal.json');

const app = express();

app.get('/', (req, res) => {
  res.send('nothing to see here. Visit /createtoken to create your token');
});

app.get('/createtoken', async (req, res) => {
  let user = { name: 'joey', favColor: 'blue', id: '123' };

  const token = jwt.sign({ user }, 'TOP_SECRET_KEY');

  console.log('token:', token);

  await fs.writeFile(
    'fakeLocal.json',
    JSON.stringify({ Authorization: `Bearer ${token}` }),
    (err) => {
      if (err) throw err;
      console.log('updated the fake localstorage in the fake browser');
    }
  );
  res.send(
    'You just made a token and stored it in the json file. Now visit /profile and /wrongsecret'
  );
});

app.get('/profile', async (req, res) => {
  console.log('Authorizationtoken:', fakeLocal.Authorization);

  const result = await jwt.verify(
    fakeLocal.Authorization.substring(7),
    'TOP_SECRET_KEY'
  );
  result.message =
    'We were able to decrypt the token because we have a valid secret in the app and the token. The user data is inside the token';

  console.log('result: ', result);

  res.json(result);
});

app.get('/wr ongsecret', async (req, res, next) => {
  try {
    await jwt.verify(fakeLocal.Authorization.substring(7), 'INCORRECT_SECRET');
    res.send('/profile');
  } catch (err) {
    console.log('error: ', err);
    return res
      .status(400)
      .send('You have failed to hack me! Your token is invalid');
  }
  res.send('comming soon: wrongsecret');
});

app.listen(3000, () => {
  console.log('server listening on port 3000');
});
