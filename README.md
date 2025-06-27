# CSSECDV Practical Exercise 2 - Secure Authentication System

A comprehensive, secure authentication system built with React and Supabase, implementing advanced security principles and best practices for user registration, login, and session management.

## Project Overview

This project implements a secure authentication system that demonstrates mastery of authentication security principles, including comprehensive input validation, secure password hashing, and protection against common security vulnerabilities.

## Technology Stack

- **Frontend**: React 18.x with Vite
- **Backend**: Supabase (PostgreSQL)
- **Routing**: React Router DOM 6.x
- **Password Hashing**: bcryptjs
- **Styling**: CSS3 with custom design
- **Security**: Custom validation pipeline with sanitization

## Project Structure

```
src/
├── components/
│   ├── NavBar.jsx              # Navigation component
│   └── ProtectedRoute.jsx      # Route protection
├── pages/
│   ├── Login.jsx               # Login page with dual authentication
│   ├── Register.jsx            # Registration with validation
│   ├── Dashboard.jsx           # Protected dashboard
│   └── ForgotPassword.jsx      # Password reset functionality
├── utils/
│   ├── validation.js           # Comprehensive validation functions
│   ├── passwordUtils.js        # Secure password hashing utilities
│   ├── databaseApi.js          # Custom authentication API
│   └── sessionManager.js       # Session management utilities
├── App.jsx                     # Main application component
├── main.jsx                    # Application entry point
├── index.css                   # Global styles
└── supabaseClient.js           # Database connection configuration
```

## Setup Instructions

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn package manager
- Supabase account

### Installation

1. **Clone the repository**
   ```bash
   git clone repository 
   cd CSSECDV-PRACTICAL-EXERCISE-2

   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Configuration**
   
   Create a `.env.local` file in the project root:
   ```env
   VITE_SUPABASE_URL=your_supabase_project_url
   VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
   ```

4. **Database Setup**
   
   Execute this SQL in your Supabase SQL Editor:
   ```sql
   -- Create custom users table
   CREATE TABLE users (
     id SERIAL PRIMARY KEY,
     username VARCHAR(30) UNIQUE NOT NULL,
     display_name VARCHAR(30) NOT NULL,
     email VARCHAR(320) UNIQUE NOT NULL,
     password_hash VARCHAR(255) NOT NULL,
     hash_algorithm VARCHAR(20) DEFAULT 'bcrypt',
     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     last_login TIMESTAMP NULL
   );

   -- Create case-insensitive unique indexes
   CREATE UNIQUE INDEX idx_users_username_lower ON users(LOWER(username));
   CREATE UNIQUE INDEX idx_users_email_lower ON users(LOWER(email));
   ```

5. **Start the development server**
   ```bash
   npm run dev
   ```

6. **Access the application**
   
   Open your browser and navigate to `http://localhost:5173`

## Security Features

### Input Validation
- Multi-layered validation pipeline
- Server-side enforcement of all rules
- Comprehensive error handling
- Input sanitization and escaping

### Password Security
- bcrypt hashing with cost factor 12
- Unique salt generation
- No plaintext storage
- Timing attack protection

### Authentication Security
- Generic error messages
- Consistent response timing
- Case-insensitive authentication
- Session management with localStorage

### Database Security
- Parameterized queries
- Unique constraints
- No sensitive data logging
- Proper error handling

## Usage

### Registration
1. Navigate to `/register`
2. Fill in username, display name, email, and password
3. System validates all inputs according to security rules
4. Successful registration stores user with hashed password

### Login
1. Navigate to `/login`
2. Enter either username or email with password
3. System automatically detects input type
4. Successful login creates session and redirects to dashboard

### Dashboard
1. Protected route requiring authentication
2. Displays user information
3. Logout functionality available

## Security Best Practices Implemented

1. **Never trust user input** - All inputs validated and sanitized
2. **Defense in depth** - Multiple security layers
3. **Principle of least privilege** - Minimal data exposure
4. **Secure by design** - Security considerations in all features
5. **Fail securely** - Safe error handling and fallbacks
