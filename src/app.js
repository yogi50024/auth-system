const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Auth Service');
});

module.exports = app;
