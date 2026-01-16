# 🚨 CRITICAL FRONTEND UPDATE: File Uploads & Avatars

## 🛑 STOP DOING THIS (Delete this logic)
1.  **DO NOT** convert images to Base64 in `ProfileScreen.tsx`.
2.  **DO NOT** send JSON bodies for image uploads.
3.  **DO NOT** use `launchImageLibrary({ includeBase64: true })`. Set `includeBase64: false`.

## ✅ DO THIS INSTEAD (New Logic)

### 1. Profile Picture Upload (FormData)
You must use `FormData` to send the file to the backend.

**Endpoint:** `POST /api/user/profile-picture`
**Headers:** `Content-Type: multipart/form-data`

#### Update `userService.js` (or wherever API calls are made):

```javascript
const uploadProfilePicture = async (imageUri) => {
  const formData = new FormData();
  
  // Extract filename and type
  const filename = imageUri.split('/').pop();
  const match = /\.(\w+)$/.exec(filename);
  const type = match ? `image/${match[1]}` : `image/jpeg`;

  // Append file - Key MUST be 'profileImage'
  formData.append('profileImage', {
    uri: imageUri,
    name: filename,
    type: type,
  });

  const response = await fetch(`${API_URL}/api/user/profile-picture`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${await AsyncStorage.getItem('authToken')}`,
      // Do NOT manually set Content-Type to multipart/form-data here; 
      // fetch/axios sets it automatically with the boundary when using FormData
    },
    body: formData,
  });

  return await response.json();
};
```

### 2. Displaying the Image
The backend now returns a **relative path** (e.g., `/uploads/profile/123.jpg`). You must prepend the `API_URL`.

```javascript
// Helper to resolve avatar source
const getAvatarSource = (photoURL) => {
  if (!photoURL) return null;
  
  // Case 1: Legacy Base64 data (Clean this up later)
  if (photoURL.startsWith('data:')) return { uri: photoURL };
  
  // Case 2: External URL (Google/Facebook)
  if (photoURL.startsWith('http')) return { uri: photoURL };
  
  // Case 3: New Backend Upload (Relative Path)
  return { uri: `${API_URL}${photoURL}` };
};

// Usage in Component
const avatarSource = getAvatarSource(user.photoURL);
const userInitials = getUserInitials(user.name);
const avatarColor = getAvatarColor(user.name);

return (
  <View>
    {avatarSource ? (
      <Image source={avatarSource} style={styles.avatar} />
    ) : (
      <View style={[styles.avatar, { backgroundColor: avatarColor }]}>
        <Text style={styles.initials}>{userInitials}</Text>
      </View>
    )}
  </View>
);
```