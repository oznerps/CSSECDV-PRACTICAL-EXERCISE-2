# CSSECDV Case Study - Secure Authentication & Session Management System

A secure authentication system developed as the culmination of three progressive practical exercises for CSSECDV (Computer Systems Security), demonstrating mastery of authentication, authorization, and session management security principles.

## Project Overview

This project implements a production-ready secure authentication system that demonstrates mastery of authentication security principles, including hybrid authentication (JWT + sessions), comprehensive input validation, secure password hashing, role-based access control (RBAC), and protection against common security vulnerabilities.

## Technology Stack

### Frontend
- **React** 18.x with Vite for fast development
- **React Router DOM** 6.x for client-side routing
- **CSS3** with custom responsive design

### Backend
- **Express.js** 4.x with security middleware
- **Supabase** (PostgreSQL) for database operations
- **JWT** (JSON Web Tokens) for stateless authentication
- **Session Management** with secure cookies

### Security & Utilities
- **bcryptjs** for secure password hashing
- **Helmet** for security headers
- **Express Rate Limit** for DoS protection
- **Express Validator** for input validation
- **Cookie Parser** for secure session cookies
- **CORS** for cross-origin request handling

## Architecture

### Hybrid Authentication System
This implementation uses a **dual-layer security approach**:

1. **JWT Tokens**: Stateless authentication for API calls
2. **Database Sessions**: Server-side session validation with automatic timeout
3. **Secure Cookies**: HttpOnly, SameSite cookies for session management
4. **Device Fingerprinting**: IP and User-Agent based session validation

### Security Features
- **30-minute session timeout** with automatic cleanup
- **Device fingerprinting** prevents session hijacking
- **Secure cookie settings** (`__Host-` prefix, httpOnly, sameSite: strict)
- **Rate limiting** on authentication endpoints
- **Comprehensive audit logging** for security events
- **Role-based access control** (RBAC) with permissions
- **Input sanitization** and validation at multiple layers

## Project Structure

```
├── server.js                      # Express server with hybrid auth middleware
├── src/
│   ├── components/
│   │   ├── NavBar.jsx             # Navigation with logout functionality
│   │   ├── ProtectedRoute.jsx     # Basic route protection
│   │   ├── requireRole.jsx        # Role-based route protection
│   │   └── RequirePermission.jsx  # Permission-based route protection
│   ├── pages/
│   │   ├── Login.jsx              # Login with hybrid authentication
│   │   ├── Register.jsx           # Registration with validation
│   │   ├── Dashboard.jsx          # Protected dashboard
│   │   ├── Profile.jsx            # User profile management
│   │   └── Admin.jsx              # Admin interface
│   ├── utils/
│   │   ├── validation.js          # Comprehensive validation functions
│   │   ├── passwordUtils.js       # Secure password hashing utilities
│   │   ├── databaseAPI.js         # Database operations with session management
│   │   ├── sessionManager.js      # Client-side session utilities
│   │   ├── jwtUtils.js            # JWT token operations
│   │   ├── authorizationUtils.js  # Permission/role verification
│   │   └── auditLogger.js         # Security event logging
│   ├── App.jsx                    # Main application with protected routes
│   ├── main.jsx                   # Application entry point
│   ├── index.css                  # Global styles
│   └── supabaseClient.js          # Database connection configuration
├── package.json                   # Dependencies and scripts
└── README.md                      # This file
```

## Setup Instructions

### Prerequisites
- **Node.js** v16.0.0 or higher
- **npm** v8.0.0 or higher
- **Supabase** account with a project

### Quick Start

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd CSSECDV-PRACTICAL-EXERCISE-2
   ```

2. **Install all dependencies**
   ```bash
   npm install
   ```
   
   This will automatically install all required dependencies including:
   - Frontend React dependencies
   - Backend Express.js and security middleware
   - Authentication utilities (JWT, bcrypt, etc.)
   - Development tools

3. **Environment Configuration**
   
   Create a `.env` file in the project root:
   ```env
   # Supabase Configuration
   VITE_SUPABASE_URL=your_supabase_project_url
   VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
   
   # JWT Configuration
   JWT_SECRET=your-super-secret-jwt-key-min-32-characters-long
   
   # Environment
   NODE_ENV=development
   ```

4. **Database Setup**
   
   Execute this SQL in your Supabase SQL Editor to create all required tables:

      -- RBAC Schema Setup for PE3

   -- Roles table
   CREATE TABLE IF NOT EXISTS roles (
      id SERIAL PRIMARY KEY,
      name VARCHAR(50) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );

   -- Permissions table 
   CREATE TABLE IF NOT EXISTS permissions (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) UNIQUE NOT NULL,
      description TEXT,
      resource VARCHAR(50) NOT NULL,
      action VARCHAR(50) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );

   -- User roles junction table
   CREATE TABLE IF NOT EXISTS user_roles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      UNIQUE(user_id, role_id)
   );

   -- Role permissions junction table
   CREATE TABLE IF NOT EXISTS role_permissions (
      id SERIAL PRIMARY KEY,
      role_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
      UNIQUE(role_id, permission_id)
   );

   -- Insert default roles
   INSERT INTO roles (name, description) VALUES 
   ('admin', 'Full system administrator with all permissions'),
   ('manager', 'Manager with user management and content oversight'),
   ('user', 'Standard user with basic access permissions')
   ON CONFLICT (name) DO NOTHING;

   -- Insert default permissions
   INSERT INTO permissions (name, description, resource, action) VALUES
   ('view_dashboard', 'Access to user dashboard', 'dashboard', 'read'),
   ('manage_users', 'Create, update, delete users', 'users', 'manage'),
   ('view_users', 'View user list and profiles', 'users', 'read'),
   ('edit_profile', 'Edit own profile information', 'profile', 'update'),
   ('admin_access', 'Access administrative functions', 'admin', 'access')
   ON CONFLICT (name) DO NOTHING;

   -- Assign permissions to roles
   INSERT INTO role_permissions (role_id, permission_id) 
   SELECT r.id, p.id 
   FROM roles r, permissions p 
   WHERE (r.name = 'admin' AND p.name IN ('view_dashboard', 'manage_users', 'view_users', 'edit_profile', 'admin_access'))
      OR (r.name = 'manager' AND p.name IN ('view_dashboard', 'manage_users', 'view_users', 'edit_profile'))
      OR (r.name = 'user' AND p.name IN ('view_dashboard', 'edit_profile'))
   ON CONFLICT (role_id, permission_id) DO NOTHING;

   -- Assign 'user' role to all existing users who don't have roles yet
   INSERT INTO user_roles (user_id, role_id)
   SELECT u.id, r.id 
   FROM users u, roles r 
   WHERE r.name = 'user'
   AND u.id NOT IN (SELECT DISTINCT user_id FROM user_roles)
   ON CONFLICT (user_id, role_id) DO NOTHING;

   -- case study onwards

   CREATE TABLE user_sessions (
   id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
   user_id uuid REFERENCES auth.users(id),
   session_token text UNIQUE NOT NULL,
   fingerprint text NOT NULL,
   expires_at timestamptz NOT NULL,
   last_accessed timestamptz DEFAULT NOW(),
   ip_address inet,
   user_agent text,
   is_active boolean DEFAULT true
   );

5. **Start the application**
   
   **Development mode (recommended):**
   npm run dev:both

   This starts both the React development server (port 5173) and the Express API server (port 3001).

   **Or start separately:**

   # Terminal 1: Start the API server
   npm run server
   
   # Terminal 2: Start the React app
   npm run dev


6. **Access the application**
   
   - **Frontend**: http://localhost:5173
   - **Backend API**: http://localhost:3001

## Authentication Flow

### Registration Process
1. User fills registration form with username, display name, email, and password
2. Frontend validates input format and strength
3. Backend performs comprehensive validation and sanitization
4. Password is hashed using bcrypt with cost factor 12
5. User is created with default 'user' role
6. Success response (no sensitive data returned)

### Login Process (Hybrid Authentication)
1. User enters username/email and password
2. Backend authenticates credentials against database
3. **JWT Token** generated with user info and roles
4. **Database session** created with device fingerprinting
5. **Secure cookie** set with session ID (`__Host-sessionid`)
6. Both token and session must be valid for API access

### Session Management
- **30-minute session timeout** with automatic extension on activity
- **Device fingerprinting** using IP address and User-Agent
- **Automatic cleanup** of expired sessions
- **Logout** invalidates both JWT and database session
- **Logout all** invalidates all user sessions across devices

### Protected Routes
- **Basic Protection**: Requires valid authentication
- **Role-Based**: Requires specific roles (admin, manager, user)
- **Permission-Based**: Requires specific permissions
- **Server-Side Validation**: All authorization checked server-side

## API Endpoints

### Authentication Endpoints
- `POST /api/auth/login` - Login with hybrid authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/logout` - Logout current session
- `POST /api/auth/logout-all` - Logout all sessions
- `POST /api/auth/refresh` - Refresh JWT token
- `GET /api/auth/verify-permission/:permission` - Verify user permission

### User Management Endpoints
- `GET /api/users` - List all users (admin/manager only)
- `PUT /api/users/:id` - Update user profile
- `PUT /api/users/:userId/roles` - Update user roles (admin only)
- `DELETE /api/users/:id` - Delete user (admin only)

### Utility Endpoints
- `GET /health` - Health check
- `GET /api/auth/test` - Test authentication and get user info

## Security Features Implemented

### 1. Hybrid Authentication Security
- **JWT + Session validation** prevents token replay attacks
- **Device fingerprinting** detects session hijacking
- **Automatic session timeout** limits exposure window
- **Secure cookie configuration** prevents XSS/CSRF attacks

### 2. Input Validation & Sanitization
- **Multi-layer validation** (client + server)
- **Input sanitization** removes dangerous characters
- **Length limits** prevent buffer overflow
- **Format validation** ensures data integrity

### 3. Password Security
- **bcrypt hashing** with cost factor 12
- **Unique salt** for each password
- **No plaintext storage** anywhere in system
- **Timing attack protection** with consistent response times

### 4. Database Security
- **Parameterized queries** prevent SQL injection
- **Unique constraints** prevent duplicate accounts
- **Foreign key constraints** maintain data integrity
- **Audit logging** tracks all security events

### 5. Network Security
- **Rate limiting** prevents brute force attacks
- **CORS configuration** restricts cross-origin requests
- **Security headers** (Helmet.js) protect against common attacks
- **HTTPS enforcement** in production

### 6. Error Handling
- **Generic error messages** prevent information leakage
- **Comprehensive logging** for security monitoring
- **Graceful degradation** maintains functionality
- **Input validation errors** are user-friendly

## Usage Examples

### Basic Authentication Check

import { isAuthenticated, getSession } from './src/utils/SessionManager';

if (isAuthenticated()) {
  const session = getSession();
  console.log('User:', session.user.username);
}


### Role-Based Access Control

import { verifyRoleServer } from './src/utils/authorizationUtils';

const hasAdminAccess = await verifyRoleServer('admin', token);
if (hasAdminAccess) {
  // Show admin interface
}


### Making Authenticated API Calls

const response = await fetch('/api/users', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  },
  credentials: 'include' // Important: includes session cookie
});


## Development Scripts

- `npm run dev` - Start React development server
- `npm run server` - Start Express API server
- `npm run dev:both` - Start both servers concurrently
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint on source code

## Production Deployment

1. **Environment Variables**:

   NODE_ENV=production
   JWT_SECRET=your-production-jwt-secret-very-long-and-secure
   VITE_SUPABASE_URL=your-production-supabase-url
   VITE_SUPABASE_ANON_KEY=your-production-supabase-key


2. **Build Application**:

   npm run build


3. **Start Production Server**:

   npm start


## Security Best Practices Implemented

1. **Never trust user input** - All inputs validated and sanitized
2. **Defense in depth** - Multiple security layers (JWT + Sessions + Validation)
3. **Principle of least privilege** - Role-based access with minimal permissions
4. **Secure by design** - Security considerations in every feature
5. **Fail securely** - Safe error handling and fallbacks
6. **Comprehensive audit** - All security events logged
7. **Session management** - Automatic timeout and cleanup
8. **Network security** - Rate limiting, CORS, security headers

## Troubleshooting

### Common Issues

1. **"Failed to fetch" errors**:
   - Ensure API server is running on port 3001
   - Check CORS configuration
   - Verify credentials: 'include' in fetch calls

2. **Authentication fails**:
   - Check JWT_SECRET is set in environment
   - Verify Supabase credentials are correct
   - Ensure user_sessions table exists

3. **Permission denied**:
   - Check user has required role/permission
   - Verify RBAC tables are properly populated
   - Check server logs for detailed errors

### Development Tips

1. **Enable debug logging**: Check browser console and server logs
2. **Test with different users**: Create users with different roles
3. **Monitor sessions**: Check user_sessions table for active sessions
4. **Audit trail**: Review audit_logs table for security events

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with proper security considerations
4. Add tests for new functionality
5. Update documentation as needed
6. Submit a pull request

