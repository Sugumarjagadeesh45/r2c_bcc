const User = require('../models/userModel');

const admin = async (req, res, next) => {
  try {
    // req.user is attached by the 'auth' middleware
    if (req.user && req.user.role === 'admin') {
      next();
    } else {
      res.status(403).json({ message: 'Access denied. Admin privileges required.' });
    }
  } catch (error) {
    res.status(500).json({ message: 'Internal server error.' });
  }
};

module.exports = admin;
