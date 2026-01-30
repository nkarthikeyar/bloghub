# BlogHub - Full Stack Blog Application

A complete blog platform with user authentication and blog management, powered by MongoDB.

## Features

- ✅ User Registration & Login
- ✅ Password Hashing with bcrypt
- ✅ Create, Read, Update, Delete Blog Posts
- ✅ Like, Comment, Share functionality
- ✅ MongoDB Database Storage
- ✅ RESTful API

## Prerequisites

Before running this project, make sure you have:

1. **Node.js** installed (v14 or higher)
   - Download from: https://nodejs.org/

2. **MongoDB** installed and running
   - Download from: https://www.mongodb.com/try/download/community
   - Or use MongoDB Atlas (cloud): https://www.mongodb.com/cloud/atlas

## Installation

1. Open PowerShell in this directory and install dependencies:
```powershell
npm install
```

2. Make sure MongoDB is running:
   - If using local MongoDB, start it with:
   ```powershell
   mongod
   ```
   - Or if MongoDB is installed as a service, it should already be running

3. Start the server:
```powershell
npm start
```

Or for development with auto-restart:
```powershell
npm run dev
```

4. Open your browser and go to:
```
http://localhost:3000/singnuppage.html
```

## API Endpoints

### User Routes
- `POST /api/signup` - Create new user account
- `POST /api/login` - Login user
- `GET /api/users` - Get all users (admin)

### Blog Routes
- `POST /api/blogs` - Create new blog post
- `GET /api/blogs` - Get all blog posts
- `GET /api/blogs/:id` - Get single blog post
- `PUT /api/blogs/:id` - Update blog post
- `DELETE /api/blogs/:id` - Delete blog post
- `POST /api/blogs/:id/like` - Like a blog post

## Database Structure

### User Collection
```javascript
{
  name: String,
  email: String (unique),
  password: String (hashed),
  createdAt: Date
}
```

### Blog Collection
```javascript
{
  title: String,
  content: String,
  excerpt: String,
  author: {
    name: String,
    email: String
  },
  tags: [String],
  likes: Number,
  comments: Number,
  shares: Number,
  createdAt: Date
}
```

## Testing with MongoDB Compass

You can view your database using MongoDB Compass:
1. Install MongoDB Compass from: https://www.mongodb.com/products/compass
2. Connect to: `mongodb://localhost:27017`
3. Select database: `bloghub`
4. View collections: `users` and `blogs`

## Troubleshooting

**Error: MongoDB connection failed**
- Make sure MongoDB is installed and running
- Check if MongoDB is running on port 27017
- Try restarting MongoDB service

**Error: Cannot find module**
- Run `npm install` again
- Make sure you're in the correct directory

**Port 3000 already in use**
- Change PORT in server.js to another number (e.g., 3001)

## Project Structure
```
signuppage&blog/
├── server.js          # Backend server with API
├── package.json       # Dependencies
├── singnuppage.html   # Signup/Login page
├── blog.html          # Blog listing page
├── 2.js              # Signup page JavaScript
├── 3.css             # Signup page CSS
├── blog.js           # Blog page JavaScript
├── blog.css          # Blog page CSS
└── README.md         # This file
```

## Next Steps

- Add JWT authentication for secure sessions
- Implement comment system
- Add image upload for blog posts
- Create user profile pages
- Add blog categories and search
