const jwt = require('jsonwebtoken');
const secret = 'mysecretsshhhhh';
const expiration = '2h';

module.exports = {
  signToken: function({ username, email, _id }) {
    const payload = { username, email, _id };
    return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
  },

  authMiddleware: function(req, res, next) {
    // allows token to be sent via req.body, req.query, or headers
    let token = req.body.token || req.query.token || req.headers.authorization;

    // separate "Bearer" from "<tokenvalue>"
    if (req.headers.authorization) {
      token = token.split(' ').pop().trim();
    }

    // if no token, return unauthorized status
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    try {
      // decode and attach user data to request object
      const { data } = jwt.verify(token, secret);
      req.user = data;
      next();
    } catch (err) {
      console.error('Invalid token', err);
      return res.status(401).json({ message: 'Invalid token' });
    }
  }
};