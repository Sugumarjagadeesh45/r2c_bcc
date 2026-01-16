// middleware/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');


const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    
    // Verify token with your JWT secret
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Find user by ID from token
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
    
    // Handle Database/Network errors specifically so frontend doesn't logout user
    if (error.name === 'MongoServerSelectionError' || error.name === 'MongoNetworkError') {
      return res.status(503).json({ 
        success: false, 
        message: 'Service unavailable. Please check your internet connection.',
        code: 'SERVICE_UNAVAILABLE'
      });
    }
    
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

module.exports = auth;


// const jwt = require('jsonwebtoken');
// const User = require('../models/userModel');

// const auth = async (req, res, next) => {
//   try {
//     const token = req.header('Authorization')?.replace('Bearer ', '');
//     if (!token) {
//       return res.status(401).json({ success: false, message: 'No token provided' });
//     }
//     const decoded = jwt.verify(token, process.env.JWT_SECRET || 'supersecret');
//     const user = await User.findById(decoded.id).select('-password');
//     if (!user) {
//       return res.status(401).json({ success: false, message: 'User not found' });
//     }
//     req.user = user;
//     next();
//   } catch (error) {
//     console.error('Auth middleware error:', error);
//     res.status(401).json({ success: false, message: 'Invalid or expired token' });
//   }
// };

// module.exports = auth;