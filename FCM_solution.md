# FCM Solution & Integration Guide

This document outlines the complete setup for handling Firebase Cloud Messaging (FCM) tokens in the application.

## 📌 Important Notes

1.  **IP Address Configuration**:
    *   Ensure your `config.js` in the frontend points to your PC's **current** local IP address (e.g., `http://192.168.104.126:5000`).
    *   **Do not use `localhost`** for Android physical devices; they cannot reach your PC via localhost.

2.  **Authentication Requirement**:
    *   The `register-token` endpoint requires the user to be logged in.
    *   The frontend must send the `Authorization: Bearer <token>` header.

3.  **Testing Workflow**:
    *   **Step 1**: Log in on a physical device (this saves the token to MongoDB).
    *   **Step 2**: Send a message from another account.
    *   **Step 3**: Check backend logs for `[DB] ✅ FCM Token saved`.

---

## 🔗 API Endpoint Reference

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/notifications/register-token` | Saves the FCM token to the user's profile | ✅ Yes |
| `POST` | `/api/notifications/remove-token` | Removes the FCM token (use on logout) | ✅ Yes |

### Request Body (Register Token)
```json
{
  "token": "fcm_token_string_here"
}
```

---

## 🛠️ Backend Implementation

### 1. User Model Update (`models/userModel.js`)
Ensure your User schema includes the `fcmTokens` array to support multiple devices.

```javascript
const userSchema = new mongoose.Schema({
  // ... existing fields ...
  fcmTokens: [{ type: String }], // ✅ Add this
  // ... existing fields ...
});
```

### 2. Notification Controller (`controllers/notificationController.js`)
Logic to add/remove tokens using `$addToSet` (prevents duplicates) and `$pull`.

```javascript
exports.registerToken = async (req, res) => {
  // ... (See updated controller file for full code)
  await User.findByIdAndUpdate(userId, { $addToSet: { fcmTokens: token } });
  // ...
};
```

### 3. Routes Setup (`routes/fcmTokenRoutes.js`)
Ensure your route file connects the endpoint to the controller.

```javascript
const express = require('express');
const router = express.Router();
const notificationController = require('../controllers/notificationController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/register-token', authMiddleware, notificationController.registerToken);
router.post('/remove-token', authMiddleware, notificationController.removeToken);

module.exports = router;
```

---

## 📱 Frontend Implementation (React Native)

### 1. Service Helper (`src/services/pushNotificationHelper.js`)

```javascript
import messaging from '@react-native-firebase/messaging';
import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';
import getApiUrl from '../utiliti/config';

const API_URL = `${getApiUrl}/api`;

// Get Token and Register
export const getFCMToken = async () => {
  try {
    const authStatus = await messaging().requestPermission();
    const enabled =
      authStatus === messaging.AuthorizationStatus.AUTHORIZED ||
      authStatus === messaging.AuthorizationStatus.PROVISIONAL;

    if (!enabled) return null;

    let fcmToken = await AsyncStorage.getItem('fcmToken');
    if (!fcmToken) {
      fcmToken = await messaging().getToken();
      if (fcmToken) await AsyncStorage.setItem('fcmToken', fcmToken);
    }

    if (fcmToken) await registerTokenInBackend(fcmToken);
    return fcmToken;
  } catch (error) {
    console.error('[FCM] Error:', error);
    return null;
  }
};

// Send to Backend
const registerTokenInBackend = async (token) => {
  try {
    const userToken = await AsyncStorage.getItem('authToken');
    if (!userToken) {
      await AsyncStorage.setItem('pendingFcmToken', token);
      return;
    }

    await axios.post(
      `${API_URL}/notifications/register-token`,
      { token },
      { headers: { Authorization: `Bearer ${userToken}` } }
    );
    console.log('[FCM] ✅ Token registered in Backend');
    await AsyncStorage.removeItem('pendingFcmToken');
  } catch (error) {
    console.error('[FCM] Backend registration failed:', error.message);
  }
};

// Call this after Login
export const registerPendingFcmToken = async () => {
  const pendingToken = await AsyncStorage.getItem('pendingFcmToken');
  if (pendingToken) await registerTokenInBackend(pendingToken);
};
```

### 2. Home Screen Integration (`src/screens/HomeScreen.js`)
Trigger the registration when the user lands on the main screen.

```javascript
import React, { useEffect } from 'react';
import { getFCMToken, registerPendingFcmToken } from '../services/pushNotificationHelper';

const HomeScreen = () => {
  useEffect(() => {
    const initNotifications = async () => {
      await registerPendingFcmToken(); // Sync any pending token
      await getFCMToken(); // Ensure token is fresh and registered
    };
    initNotifications();
  }, []);

  // ... rest of component
};
```

---

## 🐞 Troubleshooting

**Issue: "No FCM tokens found" in backend logs**
*   **Cause:** The user has not successfully hit the `/register-token` endpoint.
*   **Fix:** Check if the frontend is making the POST request. Verify the IP address in `config.js`.

**Issue: "Network Request Failed" on Android**
*   **Cause:** The phone cannot reach the PC.
*   **Fix:** Ensure PC and Phone are on the same Wi-Fi. Update `config.js` with the PC's IP (e.g., `192.168.x.x`).

**Issue: Notifications not showing in background**
*   **Cause:** Missing background handler.
*   **Fix:** Ensure `messaging().setBackgroundMessageHandler` is set in `index.js` (React Native root).