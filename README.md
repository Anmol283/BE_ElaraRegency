# 🏨 Elara Regency - Luxury Hotel Web Application
<div align="center">
<img src="https://github.com/user-attachments/assets/f75964ce-d558-4b82-a66b-302f5acc4a3f" alt="GIF" width="300" height="200">
</div>

## ✨ Overview

Elara Regency is a full-stack web application for a luxury hotel, built with Node.js, Express, MongoDB Atlas, and EJS templating. It provides a complete hotel management system with user authentication, room reservations, profile management, and an admin dashboard.

---

<div align="center">
  <table>
    <tr>
      <td><b>Anmol</b></td>
      <td>Designed UI using EJS, integrated MongoDB for data storage.</td>
    </tr>
    <tr>
      <td><b>Arshdeep Singh</b></td>
      <td>Developed frontend and backend functionality, and integrated MongoDB for data handling.</td>
    </tr>
    <tr>
      <td><b>Anshu Dhawan</b></td>
      <td>Implemented authentication middleware and route protection.</td>
    </tr>
    <tr>
      <td><b>Damandeep Singh</b></td>
      <td>Handled documentation, report writing, and testing summaries for the project.</td>
    </tr>
  </table>
</div>

---

## 🌟 Features

- **👤 User Authentication**
  - Register, login, and logout functionality  
  - Secure password hashing with Bcrypt  
  - Session management  

- **🛌 Room Reservations**
  - Browse available rooms  
  - Make and manage reservations  
  - View booking history  

- **👑 Admin Dashboard**
  - Manage users and reservations  
  - View analytics and reports  
  - Handle contact messages  

- **👨‍💼 User Profiles**
  - View and edit profile details  
  - Track reservation h


## 🛠️ Tech Stack

| Category         | Technologies                                                                                                           |
|------------------|-----------------------------------------------------------------------------------------------------------------------|
| **Backend**      | <img src="https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js" /> <img src="https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white" alt="Express.js" /> |
| **Database**     | <img src="https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB Atlas" /> |
| **Templating**   | <img src="https://img.shields.io/badge/EJS-%23B4CA65.svg?style=for-the-badge&logo=ejs&logoColor=black" alt="EJS" /> |
| **Middleware**   | <img src="https://img.shields.io/badge/Helmet-000000?style=for-the-badge&logo=helmet&logoColor=white" alt="Helmet" /> <img src="https://img.shields.io/badge/CORS-000000?style=for-the-badge&logo=cors&logoColor=white" alt="CORS" /> <img src="https://img.shields.io/badge/Morgan-000000?style=for-the-badge&logo=morgan&logoColor=white" alt="Morgan" /> <img src="https://img.shields.io/badge/Compression-000000?style=for-the-badge&logo=compression&logoColor=white" alt="Compression" /> <img src="https://img.shields.io/badge/Cookie--Parser-000000?style=for-the-badge&logo=cookie-parser&logoColor=white" alt="Cookie-Parser" /> |
| **Authentication** | <img src="https://img.shields.io/badge/Bcrypt-000000?style=for-the-badge&logo=bcrypt&logoColor=white" alt="Bcrypt" /> <img src="https://img.shields.io/badge/Express--Session-000000?style=for-the-badge&logo=express-session&logoColor=white" alt="Express-Session" /> |
| **Frontend**     | <img src="https://img.shields.io/badge/HTML5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white" alt="HTML5" /> <img src="https://img.shields.io/badge/CSS3-%231572B6.svg?style=for-the-badge&logo=css3&logoColor=white" alt="CSS3" /> <img src="https://img.shields.io/badge/JavaScript-%23F7DF1E.svg?style=for-the-badge&logo=javascript&logoColor=black" alt="JavaScript" /> |

---

## 📁 Directory Structure

```
Elara-Regency/
├── 📂 api/                    # API routes for data handling
├── 📂 middlewares/            # Application middleware
│   ├── index.js               # Exports all middleware
│   ├── authMiddleware.js      # Authentication middleware
│   ├── performanceMiddleware.js # Performance optimization
│   └── securityMiddleware.js  # Security enhancements
├── 📂 models/                 # Database models
│   ├── User.js                # User schema and model
│   ├── Reservation.js         # Reservation schema and model
│   ├── ContactMessage.js      # Contact message schema and model
│   └── users.json             # Sample user data
├── 📂 node_modules/           # Node.js dependencies
├── 📂 public/                 # Static assets
│   ├── css/                   # Stylesheets
│   ├── js/                    # Client-side JavaScript
│   └── images/                # Image assets
├── 📂 views/                  # EJS templates
│   ├── 404.ejs               # 404 page
│   ├── about.ejs             # About page
│   ├── admin-dashboard.ejs   # Admin dashboard
│   ├── blog.ejs              # Blog page
│   ├── contact.ejs           # Contact page
│   ├── error.ejs             # Error page
│   ├── home.ejs              # Home page
│   ├── location-detail.ejs   # Location detail page
│   ├── locations.ejs         # Locations page
│   ├── login.ejs             # Login page
│   ├── profile.ejs           # User profile page
│   ├── register.ejs          # Register page
│   ├── reservation.ejs       # Reservation page
│   └── rooms.ejs             # Rooms page
├── 📂 .git/                   # Git repository files
├── 📄 package.json            # Project metadata and dependencies
├── 📄 package-lock.json       # Dependency lock file
├── 📄 README.md               # Project documentation
└── 📄 server.js               # Main server file
```
---

## 🚀 Getting Started

### Prerequisites

- Node.js (v14.x or higher)
- MongoDB Atlas account
- Git

### Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Anmol283/BE_ElaraRegency
   cd elara-regency
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Set Up Environment Variables**:
   Create a `.env` file in the root directory:
   ```
   MONGO_URI=mongodb+srv://your-username:your-password@cluster0.example.mongodb.net/?retryWrites=true&w=majority
   PORT=3000
   SESSION_SECRET=your_secret_key
   ```

4. **Run the Application**:
   ```bash
   npm start
   ```

   The server will start at http://localhost:3000
---

## 🧭 Usage Guide

- **🏠 Home Page**: Visit http://localhost:3000/ to explore the hotel
- **📝 Register/Login**: Create an account or sign in
- **👤 Profile**: View your details and reservation history
- **🛌 Reservations**: Browse and book rooms
- **👑 Admin Dashboard**: Manage users and reservations (admin access only)

## 💾 Database Setup

1. **Create MongoDB Atlas Account**:
   - Sign up at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas)
   - Create a new cluster

2. **Configure Database Access**:
   - Create a database user
   - Set up network access (IP whitelist)

3. **Get Connection String**:
   - Navigate to "Connect" > "Connect your application"
   - Copy the connection string and update your `.env` file
---

## 🔒 Security Features

- **Password Protection**: All passwords are hashed using bcrypt
- **HTTP Security**: Helmet middleware for securing HTTP headers
- **CORS Protection**: Configured to prevent cross-origin issues
- **Input Validation**: Sanitization of user inputs
- **Authentication**: Protected routes with auth middleware
---

## 🤝 Contributing

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes and commit (`git commit -m "Add feature"`)
4. Push to the branch (`git push origin feature-branch`)
5. Create a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

⭐ **Star this repository if you find it useful!** ⭐
