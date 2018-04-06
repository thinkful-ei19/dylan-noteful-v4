'use strict';

const app = require('../server');
const chai = require('chai');
const chaiHttp = require('chai-http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const { TEST_MONGODB_URI } = require('../config');
const { JWT_SECRET } = require('../config');

const User = require('../models/user');

const expect = chai.expect;

chai.use(chaiHttp);

describe('Noteful API - Local Auth', function () {
  let token;
  const fullname = 'Example User';
  const username = 'exampleUser';
  const password = 'examplePass';
  const _id = '333333333333333333333300';

  before(function () {
    return mongoose.connect(TEST_MONGODB_URI)
      .then(() => mongoose.connection.db.dropDatabase());
  });

  beforeEach(function () {
    return User.hashPassword(password)
      .then(digest => User.create({
        username,
        password: digest,
        fullname,
        _id
      }));
  });

  afterEach(function () {
    return mongoose.connection.db.dropDatabase();
    // return User.remove({});
  });

  after(function () {
    return mongoose.disconnect();
  });

  describe('/api/login POST', function () {

    it('should return a valid auth token', function () {

      return chai.request(app)
        .post('/api/login')
        .send({ username, password })
        .then(res => {
          expect(res).to.have.status(200);
          expect(res.body).to.be.a('object');
          expect(res.body.authToken).to.be.a('string');

          const payload = jwt.verify(res.body.authToken, JWT_SECRET);

          expect(payload.user).to.not.have.property('password');
          expect(payload.user).to.deep.equal({ id: _id, username, fullname });
        });

    });

    it('should reject requests with no credentials', function () {

      return chai.request(app)
        .post('/api/login')
        .send({})
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(400);
        });

    });

    it('should reject requests with incorrect usernames', function () {

      return chai.request(app)
        .post('/api/login')
        .send({ username: 'falseashell', password })
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });

    });

    it('should reject requests with incorrect passwords', function () {

      return chai.request(app)
        .post('/api/login')
        .send({ username, password: 'nopenopenope' })
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });

    });

  });

  describe('/api/refresh', function () {

    it('should reject requests with no credentials', function () {

      return chai.request(app)
        .post('/api/refresh')
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });

    });

    it('should reject reqests with an invalid token', function () {

      token = jwt.sign({ username, password, fullname }, 'Incorrect Secret', { algorithm: 'HS256', expiresIn: '7d' });

      return chai.request(app)
        .post('/api/refresh')
        .set('Authorization', `Bearer ${token}`)
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });

    });

    it('should reject reqests with an expired token', function () {

      token = jwt.sign({ username, password, fullname }, JWT_SECRET, { algorithm: 'HS256', subject: username, expiresIn: Math.floor(Date.now() / 1000) - 10 });

      return chai.request(app)
        .post('/api/refresh')
        .set('Authorization', `Bearer ${token}`)
        .catch(err => err.response)
        .then(res => {
          expect(res).to.have.status(401);
        });

    });

    it('should return a valid auth token with a newer expiry date', function () {

      const user = { username, fullname };

      const token = jwt.sign({ user }, JWT_SECRET, { algorithm: 'HS256', subject: username, expiresIn: '7d' });
      const decoded = jwt.decode(token);

      return chai.request(app)
        .post('/api/refresh')
        .set('Authorization', `Bearer ${token}`)
        .then(res => {
          expect(res).to.have.status(200);
          expect(res.body).to.been.a('object');
          const authToken = res.body.authToken;
          expect(authToken).to.be.a('string');

          const payload = jwt.verify(authToken, JWT_SECRET, { algorithm: ['HS256'] });
          expect(payload.user).to.deep.equal({ username, fullname });
          expect(payload.exp).to.be.at.least(decoded.exp);
        });

    });

  });

});