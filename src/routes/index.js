const express = require('express');
const authRoutes = require('./modules/authRoutes');

const router = express.Router();

router.use('/auth', authRoutes);

module.exports = router;
