const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const protect = require('../middleware/auth');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel'); // ✅ Added missing import

console.log('authController:', Object.keys(authController));

// Helper functions for tokens
const generateAccessToken = (user) => {
  // ✅ Fixed payload to match authController and middleware expectations ({ id, userId })
  return jwt.sign({ id: user._id, userId: user.userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
};

// Note: authController uses JWT_SECRET for long-lived tokens (7d), so we align with that.

// Public routes
router.post('/check-user-id', authController.checkUserId);
router.get('/generate-user-id', authController.generateUserId);
router.post('/reset-password', authController.resetPassword);
router.post('/register', authController.register);
router.post('/verify-phone', authController.verifyPhone);
router.post('/google-signin', authController.googleSignIn);
router.post('/google-phone', authController.googlePhone);
router.post('/login', authController.login);
router.post('/check-user', authController.checkUser);
router.post('/send-otp-email', authController.sendOTPEmail);
router.post('/verify-email-otp', authController.verifyEmailOTP);
router.post('/set-password', authController.setPassword);
router.get('/check-google-config', authController.checkGoogleConfig);
router.get('/check-email-config', authController.checkEmailConfig);
router.get('/otp-status', authController.getOTPStatus);
router.post('/test-email-delivery', authController.testEmailDelivery);
router.post('/test-nodemailer-directly', authController.testNodeMailerDirectly);

// Token refresh with proper error handling
router.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }
    
    // ✅ Verify with JWT_SECRET since authController signs with it
    // If you strictly use REFRESH_TOKEN_SECRET, ensure authController uses it too. 
    // For stability now, we use JWT_SECRET to match the login token.
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    // Verify user still exists
    const user = await User.findById(decoded.id); // ✅ Fixed: use decoded.id (Mongo ID), not userId
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    const newAccessToken = generateAccessToken(user); // ✅ Pass full user object
    res.json({ 
      success: true,
      accessToken: newAccessToken 
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Refresh token expired' 
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid refresh token' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Server error during token refresh' 
    });
  }
});

// Protected routes
router.post('/update-profile', protect, authController.updateProfile);
router.post('/logout', protect, authController.logout);
router.get('/me', protect, (req, res) => {
  res.json(req.user);
});

module.exports = router;


// const express = require('express');
// const router = express.Router();
// const authController = require('../controllers/authController');
// const protect = require('../middleware/auth');
// const jwt = require('jsonwebtoken');
// const User = require('../models/userModel'); // ✅ Added missing import

// console.log('authController:', Object.keys(authController));

// // Helper functions for tokens
// const generateAccessToken = (user) => {
//   // ✅ Fixed payload to match authController and middleware expectations ({ id, userId })
//   return jwt.sign({ id: user._id, userId: user.userId }, process.env.JWT_SECRET, { expiresIn: '15m' });
// };

// // Note: authController uses JWT_SECRET for long-lived tokens (7d), so we align with that.

// // Public routes
// router.post('/check-user-id', authController.checkUserId);
// router.get('/generate-user-id', authController.generateUserId);
// router.post('/reset-password', authController.resetPassword);
// router.post('/register', authController.register);
// router.post('/verify-phone', authController.verifyPhone);
// router.post('/google-signin', authController.googleSignIn);
// router.post('/google-phone', authController.googlePhone);
// router.post('/login', authController.login);
// router.post('/check-user', authController.checkUser);
// router.post('/send-otp-email', authController.sendOTPEmail);

// router.post('/verify-email-otp', authController.verifyEmailOTP);


// router.post('/set-password', authController.setPassword);
// router.get('/check-google-config', authController.checkGoogleConfig);


// // Token refresh with proper error handling
// router.post('/refresh-token', async (req, res) => {
//   try {
//     const { refreshToken } = req.body;
    
//     if (!refreshToken) {
//       return res.status(400).json({ error: 'Refresh token is required' });
//     }
    
//     // ✅ Verify with JWT_SECRET since authController signs with it
//     // If you strictly use REFRESH_TOKEN_SECRET, ensure authController uses it too. 
//     // For stability now, we use JWT_SECRET to match the login token.
//     const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
//     // Verify user still exists
//     const user = await User.findById(decoded.id); // ✅ Fixed: use decoded.id (Mongo ID), not userId
//     if (!user) {
//       return res.status(401).json({ error: 'User not found' });
//     }
    
//     const newAccessToken = generateAccessToken(user); // ✅ Pass full user object
//     res.json({ 
//       success: true,
//       accessToken: newAccessToken 
//     });
//   } catch (error) {
//     console.error('Token refresh error:', error);
    
//     if (error.name === 'TokenExpiredError') {
//       return res.status(401).json({ 
//         success: false, 
//         error: 'Refresh token expired' 
//       });
//     }
    
//     if (error.name === 'JsonWebTokenError') {
//       return res.status(401).json({ 
//         success: false, 
//         error: 'Invalid refresh token' 
//       });
//     }
    
//     res.status(500).json({ 
//       success: false, 
//       error: 'Server error during token refresh' 
//     });
//   }
// });



// // Protected routes
// router.post('/update-profile', protect, authController.updateProfile);
// router.post('/logout', protect, authController.logout);
// router.get('/me', protect, (req, res) => {
//   res.json(req.user);
// });

// module.exports = router;
