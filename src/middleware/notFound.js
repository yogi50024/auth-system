const notFoundHandler = (req, res, next) => {
  res.status(404).send('Not Found');
};

module.exports = notFoundHandler;
