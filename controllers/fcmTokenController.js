const FCMToken = require("../models/FCMToken");

exports.registerToken = async (req, res) => {
  const { token } = req.body;
  const userId = req.user._id;

  console.log('\n[Backend-FCM] ==========================================');
  console.log('[Backend-FCM] 📱 REGISTERING FCM TOKEN');
  console.log('[Backend-FCM] User ID:', userId);
  console.log('[Backend-FCM] Token:', token ? token.substring(0, 20) + '...' : 'No token');
  console.log('[Backend-FCM] ==========================================\n');

  if (!token) {
    console.log('[Backend-FCM] ❌ FCM token is required');
    return res.status(400).json({ success: false, message: "FCM token is required." });
  }

  try {
    // Check if token already exists for this user
    const existingToken = await FCMToken.findOne({ userId });
    
    if (existingToken) {
      // Update existing token
      if (existingToken.token !== token) {
        console.log(`[Backend-FCM] 🔄 Updating existing token for user ${userId}`);
        existingToken.token = token;
        existingToken.lastUpdated = new Date();
        await existingToken.save();
        
        console.log('[Backend-FCM] ✅ Token updated successfully');
        return res.status(200).json({ 
          success: true,
          message: "FCM token updated successfully.",
          token: existingToken
        });
      } else {
        console.log('[Backend-FCM] ✅ Token already registered for this user');
        return res.status(200).json({ 
          success: true,
          message: "FCM token already registered.",
          token: existingToken
        });
      }
    }

    // Check if token exists for another user (duplicate)
    const duplicateToken = await FCMToken.findOne({ token });
    if (duplicateToken) {
      console.log(`[Backend-FCM] 🔄 Token already exists for user ${duplicateToken.userId}, updating to new user`);
      duplicateToken.userId = userId;
      duplicateToken.lastUpdated = new Date();
      await duplicateToken.save();
      
      return res.status(200).json({ 
        success: true,
        message: "FCM token reassigned successfully.",
        token: duplicateToken
      });
    }

    // Create new token record
    const newToken = new FCMToken({
      userId,
      token,
      lastUpdated: new Date()
    });

    await newToken.save();
    
    console.log('[Backend-FCM] ✅ New FCM token registered successfully');
    console.log('[Backend-FCM] Token ID:', newToken._id);

    res.status(200).json({ 
      success: true,
      message: "FCM token registered successfully.",
      token: newToken
    });
  } catch (error) {
    console.error('[Backend-FCM] ❌ Error registering FCM token:', error.message);
    console.error('[Backend-FCM] Error details:', error);
    
    if (error.code === 11000) {
      if (error.keyPattern && error.keyPattern.token) {
        return res.status(409).json({ 
          success: false, 
          message: "This FCM token is already registered to another user." 
        });
      }
      if (error.keyPattern && error.keyPattern.userId) {
        return res.status(409).json({ 
          success: false, 
          message: "This user already has a registered token." 
        });
      }
    }
    
    res.status(500).json({ 
      success: false, 
      message: "Internal server error.",
      error: error.message 
    });
  }
};

// Add a test endpoint
exports.testFCM = async (req, res) => {
  try {
    const userId = req.user._id;
    
    console.log(`[FCM-Test] 🔧 Testing FCM for user: ${userId}`);
    
    // Check if user has FCM token
    const tokens = await FCMToken.find({ userId });
    console.log(`[FCM-Test] Found ${tokens.length} tokens for user`);
    
    // Log token details
    tokens.forEach((token, index) => {
      console.log(`[FCM-Test] Token ${index + 1}: ${token.token.substring(0, 20)}...`);
      console.log(`[FCM-Test] Last Updated: ${token.lastUpdated}`);
    });

    res.json({
      success: true,
      message: 'FCM test completed',
      hasTokens: tokens.length > 0,
      tokenCount: tokens.length,
      tokens: tokens.map(t => ({
        id: t._id,
        tokenPreview: t.token.substring(0, 20) + '...',
        lastUpdated: t.lastUpdated
      }))
    });
    
  } catch (error) {
    console.error('[FCM-Test] Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
};





// const FCMToken = require("../models/FCMToken");

// exports.registerToken = async (req, res) => {
//   const { token } = req.body;
//   const userId = req.user._id; // Correctly get userId from authenticated user

//   if (!token) {
//     return res.status(400).json({ success: false, message: "FCM token is required." });
//   }

//   try {
//     // Use findOneAndUpdate with upsert to create or update the token
//     const updatedToken = await FCMToken.findOneAndUpdate(
//       { userId }, // Find by userId
//       { token, lastUpdated: new Date() }, // Update the token and timestamp
//       { new: true, upsert: true, setDefaultsOnInsert: true }
//     );

//     res.status(200).json({ 
//         success: true,
//         message: "FCM token registered successfully.",
//         token: updatedToken
//     });
//   } catch (error) {
//     console.error("Error registering FCM token:", error);
//     // Check for duplicate key error for the token
//     if (error.code === 11000 && error.keyPattern && error.keyPattern.token) {
//         return res.status(409).json({ success: false, message: "This FCM token is already registered to another user." });
//     }
//     res.status(500).json({ success: false, message: "Internal server error." });
//   }
// };
