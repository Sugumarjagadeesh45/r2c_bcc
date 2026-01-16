const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const FCMToken = require('../models/FCMToken');
const fcmService = require('../services/fcmService');

/**
 * @route   GET /api/test/health
 * @desc    Health check for FCM service
 * @access  Private
 */



// In D:\good_r2c-main\routes\testFCMRoutes.js, add:
router.get('/firebase-debug', auth, async (req, res) => {
  try {
    const firebaseConfig = require('../config/firebase');
    
    console.log('[Firebase-Debug] Checking Firebase configuration...');
    
    // Get admin instance
    const admin = firebaseConfig.getAdmin();
    
    const debugInfo = {
      adminExists: !!admin,
      adminType: typeof admin,
      adminAppsCount: admin?.apps?.length || 0,
      messagingAvailable: !!(admin && admin.messaging),
      firebaseConfigKeys: Object.keys(firebaseConfig),
      firebaseStatus: firebaseConfig.getFirebaseStatus()
    };
    
    console.log('[Firebase-Debug] Debug info:', debugInfo);
    
    // Try to send a test message
    let testResult = null;
    if (admin && admin.messaging) {
      try {
        // This is a dry run with a fake token
        const fakeToken = 'fake_token_for_testing_123';
        testResult = await admin.messaging().send({
          token: fakeToken,
          notification: { title: 'Test', body: 'Test' }
        }, true); // dryRun=true doesn't actually send
      } catch (error) {
        testResult = {
          error: error.message,
          code: error.code,
          stack: error.stack
        };
      }
    }
    
    res.json({
      success: true,
      debugInfo,
      testResult
    });
    
  } catch (error) {
    console.error('[Firebase-Debug] Error:', error);
    res.status(500).json({
      success: false,
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Add to D:\good_r2c-main\routes\testFCMRoutes.js
router.get('/all-tokens', auth, async (req, res) => {
  try {
    const FCMToken = require('../models/FCMToken');
    const User = require('../models/userModel');
    
    const allTokens = await FCMToken.find({})
      .populate('userId', 'userId name email');
    
    console.log(`[All-Tokens] Found ${allTokens.length} tokens total`);
    
    res.json({
      success: true,
      totalTokens: allTokens.length,
      tokens: allTokens.map(token => ({
        id: token._id,
        userId: token.userId?._id,
        userName: token.userId?.name,
        userUserId: token.userId?.userId,
        tokenPreview: token.token ? token.token.substring(0, 30) + '...' : 'No token',
        tokenLength: token.token ? token.token.length : 0,
        lastUpdated: token.lastUpdated,
        createdAt: token.createdAt
      }))
    });
    
  } catch (error) {
    console.error('[All-Tokens] Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});




// Add to D:\good_r2c-main\routes\testFCMRoutes.js
router.post('/add-test-token', auth, async (req, res) => {
  try {
    const FCMToken = require('../models/FCMToken');
    const { token } = req.body;
    const userId = req.user._id;
    
    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Token is required'
      });
    }
    
    console.log(`[Add-Test-Token] Adding token for user ${userId}`);
    console.log(`[Add-Test-Token] Token: ${token.substring(0, 30)}...`);
    
    // Check if user already has a token
    const existingToken = await FCMToken.findOne({ userId });
    
    if (existingToken) {
      console.log(`[Add-Test-Token] Updating existing token for user ${userId}`);
      existingToken.token = token;
      existingToken.lastUpdated = new Date();
      await existingToken.save();
      
      return res.json({
        success: true,
        message: 'Token updated',
        token: {
          id: existingToken._id,
          userId: existingToken.userId,
          tokenPreview: existingToken.token.substring(0, 30) + '...'
        }
      });
    }
    
    // Create new token
    const newToken = new FCMToken({
      userId,
      token,
      lastUpdated: new Date()
    });
    
    await newToken.save();
    
    console.log(`[Add-Test-Token] New token created: ${newToken._id}`);
    
    res.json({
      success: true,
      message: 'Token added successfully',
      token: {
        id: newToken._id,
        userId: newToken.userId,
        tokenPreview: newToken.token.substring(0, 30) + '...'
      }
    });
    
  } catch (error) {
    console.error('[Add-Test-Token] Error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'This token is already registered to another user'
      });
    }
    
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});



router.get('/health', auth, async (req, res) => {
  try {
    res.json({
      success: true,
      message: 'FCM service is healthy',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});







/**
 * @route   GET /api/test/firebase-status
 * @desc    Check Firebase configuration
 * @access  Private
 */
router.get('/firebase-status', auth, async (req, res) => {
  try {
    const { getFirebaseStatus } = require('../config/firebase');
    const status = getFirebaseStatus();
    
    console.log('[Firebase-Status] Returning status:', status);
    
    res.json({
      success: true,
      firebase: status
    });
  } catch (error) {
    console.error('[Firebase-Status] ❌ Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});




/**
 * @route   GET /api/test/fcm-status
 * @desc    Get FCM status for current user
 * @access  Private
 */
router.get('/fcm-status', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    console.log(`[FCM-Status] Checking status for user: ${userId}`);
    
    const tokens = await FCMToken.find({ userId });
    
    console.log(`[FCM-Status] Found ${tokens.length} token(s)`);
    
    res.json({
      success: true,
      hasTokens: tokens.length > 0,
      tokenCount: tokens.length,
      tokens: tokens.map(t => ({
        id: t._id,
        tokenPreview: t.token.substring(0, 20) + '...',
        lastUpdated: t.lastUpdated,
        createdAt: t.createdAt
      }))
    });
  } catch (error) {
    console.error('[FCM-Status] ❌ Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/**
 * @route   POST /api/test/send-test/:userId
 * @desc    Send test notification to a user
 * @access  Private
 */
router.post('/send-test/:userId', auth, async (req, res) => {
  try {
    const { userId } = req.params;
    const sender = req.user;
    
    console.log(`[Test-FCM] Sending test notification to user: ${userId}`);
    
    // Create a test message object
    const testMessage = {
      _id: 'test_' + Date.now(),
      text: 'This is a test notification from the backend',
      createdAt: new Date()
    };
    
    // Create a test conversation ID
    const testConversationId = 'test_conversation_' + Date.now();
    
    // Send the notification
    const result = await fcmService.sendNewMessageNotification(
      userId,
      sender,
      testMessage,
      testConversationId
    );
    
    res.json({
      success: true,
      message: 'Test notification sent successfully',
      result: result
    });
    
  } catch (error) {
    console.error('[Test-FCM] Error sending test notification:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

/**
 * @route   POST /api/test/manual-test
 * @desc    Manually test FCM with a token
 * @access  Private
 */
router.post('/manual-test', auth, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user._id;
    
    console.log(`[Manual-Test] Testing FCM token: ${token ? token.substring(0, 30) + '...' : 'No token'}`);
    
    if (!token) {
      return res.status(400).json({
        success: false,
        message: 'Token is required'
      });
    }
    
    // Test if token looks valid
    const isValid = token.length > 30 && 
                   (token.includes(':APA91b') || token.includes('fcm') || token.includes('AAAA') || token.includes('fk3Kp8DjT0yf'));
    
    if (!isValid) {
      console.log(`[Manual-Test] ❌ Token looks invalid: ${token.length} chars`);
      return res.status(400).json({
        success: false,
        message: 'Token format appears invalid. Valid FCM tokens are 30+ characters and contain :APA91b',
        tokenLength: token.length,
        sampleToken: 'Example: fk3Kp8DjT0yf...:APA91bH6dSYO5TXfK9G3z0C3...'
      });
    }
    
    // Register the token
    const existingToken = await FCMToken.findOne({ userId });
    if (existingToken) {
      existingToken.token = token;
      existingToken.lastUpdated = new Date();
      await existingToken.save();
    } else {
      const newToken = new FCMToken({
        userId,
        token
      });
      await newToken.save();
    }
    
    // Send test notification
    const testPayload = {
      notification: {
        title: 'Manual Test',
        body: 'FCM manual test notification'
      },
      data: {
        type: 'manual_test',
        timestamp: new Date().toISOString()
      }
    };
    
    await fcmService.sendToUser(userId, testPayload);
    
    res.json({
      success: true,
      message: 'Test notification sent',
      tokenRegistered: true,
      tokenLength: token.length,
      tokenPreview: token.substring(0, 30) + '...'
    });
    
  } catch (error) {
    console.error('[Manual-Test] Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

module.exports = router;




// const express = require('express');
// const router = express.Router();
// const testFCMController = require('../controllers/testFCMController');
// const auth = require('../middleware/auth');

// /**
//  * @route   GET /api/test/health
//  * @desc    Health check for FCM service
//  * @access  Private
//  */
// router.get('/health', auth, testFCMController.healthCheck);

// /**
//  * @route   GET /api/test/fcm-status
//  * @desc    Get FCM status for current user
//  * @access  Private
//  */
// router.get('/fcm-status', auth, async (req, res) => {
//   try {
//     const FCMToken = require('../models/FCMToken');
//     const userId = req.user._id;
    
//     console.log(`[FCM-Status] Checking status for user: ${userId}`);
    
//     const tokens = await FCMToken.find({ userId });
    
//     console.log(`[FCM-Status] Found ${tokens.length} token(s)`);
    
//     res.json({
//       success: true,
//       hasTokens: tokens.length > 0,
//       tokenCount: tokens.length,
//       tokens: tokens.map(t => ({
//         id: t._id,
//         tokenPreview: t.token.substring(0, 20) + '...',
//         lastUpdated: t.lastUpdated,
//         createdAt: t.createdAt
//       }))
//     });
//   } catch (error) {
//     console.error('[FCM-Status] ❌ Error:', error);
//     res.status(500).json({
//       success: false,
//       message: error.message
//     });
//   }
// });

// /**
//  * @route   POST /api/test/send-test/:userId
//  * @desc    Send test notification to a user
//  * @access  Private
//  */
// router.post('/send-test/:userId', auth, testFCMController.sendTestNotification);

// /**
//  * @route   GET /api/test/fcm-config
//  * @desc    Check FCM configuration
//  * @access  Private
//  */


// // Add this route to testFCMRoutes.js
// router.post('/manual-test', auth, async (req, res) => {
//   try {
//     const { token } = req.body;
//     const userId = req.user._id;
    
//     console.log(`[Manual-Test] Testing FCM token: ${token ? token.substring(0, 30) + '...' : 'No token'}`);
    
//     if (!token) {
//       return res.status(400).json({
//         success: false,
//         message: 'Token is required'
//       });
//     }
    
//     // Test if token looks valid
//     const isValid = token.length > 100 && 
//                    (token.includes(':APA91b') || token.includes('fcm') || token.includes('AAAA'));
    
//     if (!isValid) {
//       console.log(`[Manual-Test] ❌ Token looks invalid: ${token.length} chars`);
//       return res.status(400).json({
//         success: false,
//         message: 'Token format appears invalid. Valid FCM tokens are 152+ characters and contain :APA91b',
//         tokenLength: token.length,
//         sampleToken: 'Example: fk3Kp8DjT0yf...:APA91bH6dSYO5TXfK9G3z0C3...'
//       });
//     }
    
//     // Register the token
//     const existingToken = await FCMToken.findOne({ userId });
//     if (existingToken) {
//       existingToken.token = token;
//       existingToken.lastUpdated = new Date();
//       await existingToken.save();
//     } else {
//       const newToken = new FCMToken({
//         userId,
//         token
//       });
//       await newToken.save();
//     }
    
//     // Send test notification
//     const testPayload = {
//       notification: {
//         title: 'Manual Test',
//         body: 'FCM manual test notification'
//       },
//       data: {
//         type: 'manual_test',
//         timestamp: new Date().toISOString()
//       }
//     };
    
//     await fcmService.sendToUser(userId, testPayload);
    
//     res.json({
//       success: true,
//       message: 'Test notification sent',
//       tokenRegistered: true,
//       tokenLength: token.length,
//       tokenPreview: token.substring(0, 30) + '...'
//     });
    
//   } catch (error) {
//     console.error('[Manual-Test] Error:', error);
//     res.status(500).json({
//       success: false,
//       message: error.message
//     });
//   }
// });



// router.get('/fcm-config', auth, async (req, res) => {
//   try {
//     const config = {
//       success: true,
//       config: {
//         firebaseProjectId: process.env.FIREBASE_PROJECT_ID,
//         firebaseClientEmail: process.env.FIREBASE_CLIENT_EMAIL,
//         firebaseInitialized: true,
//         nodeEnv: process.env.NODE_ENV || 'development'
//       }
//     };
    
//     console.log('[FCM-Config] Returning config:', config);
    
//     res.json(config);
//   } catch (error) {
//     console.error('[FCM-Config] ❌ Error:', error);
//     res.status(500).json({
//       success: false,
//       message: error.message
//     });
//   }
// });

// module.exports = router;