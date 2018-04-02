'use strict';

const express = require('express');
const router = express.Router();

// const mongoose = require('mongoose');
const passport = require('passport');

const options = { session: false, failWithError: true };

const localAuth = passport.authenticate('local', options);

router.post('/login', localAuth, (req, res) => {
  return res.json(req.user);
});

module.exports = router;