#  API Documentation & Frontend Integration Guide

## 1. ⚡ Thunder Client / Postman Testing Guide

Use this to verify your backend is working correctly before debugging the frontend.

### 🟢 POST: Upload Profile Pictu
*   **URL:** `http://localhost:5000/api/user/profile-picture`
*   **Method:** `POST`
*   **Auth:** Bearer Token (Header: `Authorization: Bearer <YOUR_TOKEN>`)
*   **Body Type:** `Multipart Form`
*   **Fields:**
    *   `profileImage`: [Select a file] (Type: File)
*   **Expected Result (200 OK):**
    ```json
    {
      "success": true,
      "message": "Profile picture updated successfully",
      "profilePicture": "/uploads/profile/17000000_USER.jpg"
    }
    ```

### 🔵 GET: User Profile
*   **URL:** `http://localhost:5000/api/user/profile`
*   **Method:** `GET`
*   **Auth:** Bearer Token
*   **Expected Result (200 OK):** Returns user object with `photoURL`.

### 🟠 PUT: Update Profile
*   **URL:** `http://localhost:5000/api/user/profile`
*   **Method:** `PUT`
*   **Auth:** Bearer Token
*   **Body (JSON):**
    ```json
    {
      "bio": "New bio",
      "location": "New York"
    }
    ```

---

## 2. 🚨 CRITICAL FRONTEND FIXES

### ❌ Error 1: "Profile picture file is required" (400)
**Cause:** The field name in `FormData` does not match the backend expectation.
**Fix:** The backend expects the field name `profileImage`.

### ❌ Error 2: "Network request failed"
**Cause:** You are manually setting `Content-Type: multipart/form-data`.
**Fix:** **REMOVE** that header. `fetch` sets it automatically with the boundary.

### ✅ Correct Upload Function (Copy-Paste)

```javascript
const uploadProfilePicture = async (imageUri, token) => {
  try {
    const formData = new FormData();

    // 1. Prepare file data
    const filename = imageUri.split('/').pop();
    const match = /\.(\w+)$/.exec(filename);
    const type = match ? `image/${match[1]}` : 'image/jpeg';

    // ⚠️ KEY MUST BE 'profileImage'
    formData.append('profileImage', {
      uri: imageUri,
      name: filename,
      type: type,
    });

    console.log('📤 Sending upload request...');

    // 2. Send Request
    const response = await fetch(`${API_URL}/api/user/profile-picture`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/json',
        // 🛑 DO NOT ADD Content-Type: multipart/form-data
      },
      body: formData,
    });

    const result = await response.json();
    console.log('📥 Upload response:', result);
    
    if (!response.ok) {
        throw new Error(result.message || 'Upload failed');
    }
    
    return result;

  } catch (error) {
    console.error('❌ Upload failed:', error);
    throw error;
  }
};
```