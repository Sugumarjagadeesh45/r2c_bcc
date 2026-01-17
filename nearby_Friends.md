# Nearby Friends & Live Location System - Frontend Implementation Guide

## 1. 🚨 Critical Fix for Current Error
You are missing the geolocation package. Run this command in your project root (`D:\rrr222ccc\f_c`):

```bash
npm install @react-native-community/geolocation
```

Then rebuild the app.

---

## 2. API Endpoints

### A. Update User Location
**Endpoint:** `POST http://localhost:5000/api/nearby/location`
**Headers:** `Authorization: Bearer <token>`
**Body:**
```json
{
  "latitude": 37.78825,
  "longitude": -122.4324
}
```
**When to call:**
1. **App Open:** Inside `useEffect` on the Home/Map screen.
2. **Foreground:** Listen to `AppState` changes; send when app comes to 'active'.
3. **Movement:** If using `watchPosition`, send updates when distance changes by > 50m.
4. **Periodic:** Optional fallback every 60 seconds.

### B. Get Nearby Users
**Endpoint:** `GET http://localhost:5000/api/nearby/users`
**Headers:** `Authorization: Bearer <token>`
**Query Params:**
- `radius` (optional): Search radius in meters (default: 2000).
- `includeSelf` (optional): Set to `true` to see yourself (useful for testing with 1 user).

**Example URL:** 
`http://localhost:5000/api/nearby/users?radius=5000&includeSelf=true`

**Response Structure:**
```json
{
  "success": true,
  "count": 5,
  "isPremium": false,
  "users": [
    {
      "_id": "653a...",
      "userId": "john_doe",
      "name": "John Doe",
      "profilePicture": "http://...",
      "isOnline": true,
      "lastSeen": "2023-10-27T10:00:00.000Z",
      "distance": 150
    }
  ]
}
```

## 3. Logic & Privacy Notes
- **Normal Users:** Will only receive users who are currently `isOnline: true`.
- **Premium Users:** Will receive all users active within the last 24 hours.
- **Socket.IO:** The backend automatically handles online/offline status when the socket connects/disconnects. You do not need to manually emit "online" events, just ensure the socket is connected with the user's token.
- **Data Cleanup:** Location data is automatically deleted from the database after 24 hours.

## 4. Troubleshooting Common Errors

### ❌ Error: "unable to find index for $geoNear query"
- **Cause:** You are hitting the wrong endpoint (`/api/user/nearby`).
- **Fix:** Use the correct endpoint: `/api/nearby/users`. The `UserLocation` collection has the required index, but your old `User` collection does not.

### ❌ Error: 404 on `/api/user/recent`
- **Fix:** There is no separate "recent" endpoint. Use `/api/nearby/users`. The backend automatically checks if the user is **Premium** and returns users active in the last 24 hours if applicable.

### ❌ Error: "Your location is not set"
- **Cause:** The backend cannot find your location in the database.
- **Fix:** Ensure you call `POST /api/nearby/location` successfully **before** calling `GET /api/nearby/users`.
- **Debug:** Check the server console logs (added in the latest update) to see which User ID is being searched for.

### ❌ Result: "count: 0" (Empty List)
- **Cause:** You are the only user in the area, and the system hides you from yourself.
- **Fix:** Add `&includeSelf=true` to your GET request URL to verify the data is there.

## 5. 🚨 Android Crash Fix: "Tried to use permissions API while not attached to an Activity"

**The Issue:**
You see `java.lang.IllegalStateException` in your logs. This happens because the app is trying to request location permissions **before** the screen is fully visible or while the app is in the background/transitioning.

**The Fix (Apply in `NearbyFriends.tsx` and `ProfileScreen.tsx`):**

1.  **Import `AppState` and `InteractionManager`:**
    ```javascript
    import { AppState, Platform, PermissionsAndroid, InteractionManager } from 'react-native';
    ```

2.  **Wrap your Location Request:**
    Don't just call `requestLocationPermission()` inside `useEffect`. Wait for the screen to be ready.

    ```javascript
    useEffect(() => {
      // 1. Wait for navigation animations to finish (Prevents "not attached to Activity" crash)
      const task = InteractionManager.runAfterInteractions(() => {
        checkPermission();
      });

      return () => task.cancel();
    }, []);

    const checkPermission = async () => {
      // 2. Only request if App is Active (Visible)
      if (AppState.currentState !== 'active') {
        console.log('App is backgrounded, skipping permission request');
        return;
      }

      if (Platform.OS === 'android') {
        try {
          // This line crashes if called too early, InteractionManager prevents that
          const granted = await PermissionsAndroid.request(
            PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
          );
          if (granted === PermissionsAndroid.RESULTS.GRANTED) {
            getCurrentLocation(); // Call your location function here
          } else {
            console.log('Location permission denied');
          }
        } catch (err) {
          console.warn('Permission Error:', err);
        }
      }
    };
    ```