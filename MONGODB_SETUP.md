# MongoDB Installation & Setup Guide

## Step 1: Install MongoDB

### Option A: Install MongoDB Locally (Recommended for Development)

1. **Download MongoDB Community Server**
   - Go to: https://www.mongodb.com/try/download/community
   - Select your Windows version
   - Download and run the installer

2. **During Installation:**
   - Choose "Complete" installation
   - Install MongoDB as a Service (check the box)
   - Install MongoDB Compass (optional but recommended)

3. **Verify Installation:**
   Open PowerShell and run:
   ```powershell
   mongod --version
   ```

### Option B: Use MongoDB Atlas (Cloud - Free)

1. Go to: https://www.mongodb.com/cloud/atlas/register
2. Create a free account
3. Create a new cluster (free tier)
4. Get your connection string
5. Update `server.js` line 13:
   ```javascript
   const MONGODB_URI = 'your-mongodb-atlas-connection-string';
   ```

## Step 2: Start MongoDB Service

### If MongoDB is installed as a service:
It should start automatically. You can check with:
```powershell
Get-Service MongoDB
```

### If not running as a service:
Open a new PowerShell window and run:
```powershell
mongod
```
Keep this window open while using the app.

## Step 3: Start Your Application

1. Open PowerShell in your project directory:
```powershell
cd "c:\Users\Karthikeya\Desktop\k computer\files\java full stack\html&css\hydofficework\signuppage&blog"
```

2. Start the server:
```powershell
npm start
```

3. Open your browser and go to:
```
http://localhost:3000/singnuppage.html
```

## Step 4: Test Your Application

1. **Create an account:**
   - Fill in the signup form
   - Click "Create Account"
   - You should be redirected to the blog page

2. **View your data in MongoDB:**
   - Open MongoDB Compass
   - Connect to: `mongodb://localhost:27017`
   - Open database: `bloghub`
   - View collections: `users` and `blogs`

## Troubleshooting

### Error: "MongoNetworkError: connect ECONNREFUSED"
**Solution:** MongoDB is not running. Start MongoDB first.

### Error: "Port 3000 is already in use"
**Solution:** 
- Close other applications using port 3000
- Or change the port in `server.js` (line 7)

### Error: "Cannot find module 'express'"
**Solution:** Run `npm install` again

### MongoDB not starting as service
**Solution:** 
1. Open Services (search in Windows)
2. Find "MongoDB"
3. Right-click > Start

## Quick Commands Reference

```powershell
# Install dependencies
npm install

# Start server
npm start

# Start server with auto-reload (development)
npm run dev

# Check MongoDB service status
Get-Service MongoDB

# Start MongoDB service
Start-Service MongoDB
```

## Using MongoDB Compass (GUI)

1. Open MongoDB Compass
2. Connection String: `mongodb://localhost:27017`
3. Click "Connect"
4. You'll see your `bloghub` database
5. Explore `users` and `blogs` collections

## Alternative: MongoDB Atlas Setup

If you prefer cloud database:

1. Create account at https://mongodb.com/cloud/atlas
2. Create a free cluster
3. Click "Connect" > "Connect your application"
4. Copy connection string
5. Replace in `server.js`:
   ```javascript
   const MONGODB_URI = 'mongodb+srv://username:password@cluster.mongodb.net/bloghub';
   ```
6. Add your IP to whitelist in Atlas
7. Create database user with password

That's it! Your blog app is now connected to MongoDB! 🚀
