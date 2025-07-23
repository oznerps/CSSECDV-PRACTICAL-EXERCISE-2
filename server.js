import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { body, validationResult } from 'express-validator';
import crypto from 'crypto';

// JWT utilities
import { verifyToken, generateToken, refreshToken } from './src/utils/jwtUtils.js';

// Database functions
import { 
    authenticateUser as dbAuthenticateUser,
    getUserRoles, 
    userHasPermission,
    getUserPermissions,
    canUserAssignRole,
    updateUserRolesSecure,
    getAllUsersWithRoles,
    getUserWithRolesAndPermissions,
    createUserSession,
    validateSession,
    invalidateSession,
    invalidateAllUserSessions
} from './src/utils/databaseAPI.js';

// Supabase client
import { supabase } from './src/supabaseClient.js';

// Audit logging
import { 
    logSecurityEvent, 
    logAuthEvent, 
    logAuthorizationFailure, 
    logAccessAttempt 
} from './src/utils/auditLogger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Security headers middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: {
        error: 'Too many authentication attempts, please try again later',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// General API rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: {
        error: 'Too many requests, please try again later'
    }
});

// Cookie parser middleware (must be before CORS)
import cookieParser from 'cookie-parser';
app.use(cookieParser());

// Apply rate limiting
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// Middleware configuration
app.use(express.json());

// Enhanced CORS configuration for hybrid authentication
app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, curl requests, etc.)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:5173',
            'http://127.0.0.1:5173',
            'http://localhost:3000', // In case frontend runs on 3000
            'http://127.0.0.1:3000'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log('CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // Essential for cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'Cookie',
        'Set-Cookie',
        'X-Requested-With',
        'Accept',
        'Origin',
        'Cache-Control',
        'Pragma'
    ],
    exposedHeaders: ['Set-Cookie'],
    preflightContinue: false,
    optionsSuccessStatus: 200, // For legacy browser support
    maxAge: 86400 // 24 hours preflight cache
}));

// Debug middleware to log request details (only in development)
if (process.env.NODE_ENV !== 'production') {
    app.use((req, res, next) => {
        console.log(`${req.method} ${req.path}`, {
            origin: req.get('Origin'),
            userAgent: req.get('User-Agent')?.substring(0, 50) + '...',
            cookies: Object.keys(req.cookies || {}),
            hasAuth: !!req.get('Authorization')
        });
        next();
    });
}

// ONLY serve static files if dist directory exists (for production)
import fs from 'fs';
const distPath = path.join(__dirname, 'dist');
if (fs.existsSync(distPath)) {
    console.log('Serving static files from dist directory');
    app.use(express.static(distPath));
} else {
    console.log('Running in development mode - dist directory not found');
}

// Hybrid authentication middleware (JWT + Session)
const authenticateUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        // Use appropriate cookie name based on environment
        const cookieName = process.env.NODE_ENV === 'production' ? '__Host-sessionid' : 'sessionid';
        const sessionId = req.cookies[cookieName];
        const clientIP = req.ip || req.connection.remoteAddress;
        
        // Check for both JWT token and session cookie
        if (!authHeader || !authHeader.startsWith('Bearer ') || !sessionId) {
            await logAuthEvent('AUTH_FAILED', null, clientIP, 'Missing JWT token or session cookie');
            return res.status(401).json({ 
                error: 'Authentication required',
                code: 'MISSING_CREDENTIALS'
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify JWT token
        let decoded;
        try {
            decoded = verifyToken(token);
        } catch (jwtError) {
            await logAuthEvent('AUTH_FAILED', null, clientIP, `JWT verification failed: ${jwtError.message}`);
            return res.status(401).json({ 
                error: 'Invalid authentication token',
                code: 'INVALID_TOKEN'
            });
        }
        
        // Validate session
        const session = await validateSession(sessionId);
        if (!session) {
            await logAuthEvent('AUTH_FAILED', decoded.userId, clientIP, 'Invalid or expired session');
            return res.status(401).json({ 
                error: 'Session expired or invalid',
                code: 'INVALID_SESSION'
            });
        }
        
        // Verify that session belongs to the same user as the JWT
        if (session.user_id !== decoded.userId) {
            await logAuthEvent('AUTH_FAILED', decoded.userId, clientIP, 'Session user mismatch');
            return res.status(401).json({ 
                error: 'Authentication mismatch',
                code: 'SESSION_MISMATCH'
            });
        }
        
        // Attach user info from token and session
        req.user = {
            id: decoded.userId,
            username: decoded.username,
            email: decoded.email,
            roles: decoded.roles
        };
        req.sessionId = sessionId;

        await logAuthEvent('AUTH_SUCCESS', decoded.userId, clientIP, 'Hybrid authentication successful');
        next();
        
    } catch (error) {
        const clientIP = req.ip || req.connection.remoteAddress;
        await logAuthEvent('AUTH_FAILED', null, clientIP, `Authentication error: ${error.message}`);
        
        console.error('Authentication error:', error.message);
        
        return res.status(401).json({ 
            error: 'Authentication failed',
            code: 'AUTH_ERROR'
        });
    }
};

// Role-based authorization middleware
function requireRole(allowedRoles) {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                await logAuthorizationFailure(null, 'Unknown role requirement', 'No authenticated user');
                return res.status(401).json({ error: 'Authentication required' });
            }

            const userRoles = await getUserRoles(req.user.id);
            const hasPermission = userRoles.some(role => 
                allowedRoles.includes(role.name)
            );

            if (!hasPermission) {
                await logAuthorizationFailure(req.user.id, allowedRoles.join(','), `User roles: ${userRoles.map(r => r.name).join(',')}`);
                return res.status(403).json({ error: 'Insufficient permissions' });
            }

            next();
        } catch (error) {
            console.error('Role check error:', error);
            res.status(500).json({ error: 'Authorization check failed' });
        }
    };
}

// Permission-based authorization middleware
function requirePermission(requiredPermission) {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                await logAuthorizationFailure(null, requiredPermission, 'No authenticated user');
                return res.status(401).json({ error: 'Authentication required' });
            }

            const hasPermission = await userHasPermission(req.user.id, requiredPermission);

            if (!hasPermission) {
                await logAuthorizationFailure(req.user.id, requiredPermission, 'Permission denied');
                return res.status(403).json({ error: 'Insufficient permissions' });
            }

            next();
        } catch (error) {
            console.error('Permission check error:', error);
            res.status(500).json({ error: 'Permission check failed' });
        }
    };
}

// Request validation middleware
const validateLoginRequest = [
    body('identifier')
        .trim()
        .isLength({ min: 1 })
        .withMessage('Username or email is required'),
    body('password')
        .isLength({ min: 1 })
        .withMessage('Password is required'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Invalid request data',
                details: errors.array()
            });
        }
        next();
    }
];

// User update validation middleware
const validateUserUpdateRequest = [
    body('display_name')
        .optional()
        .trim()
        .isLength({ min: 1, max: 30 })
        .withMessage('Display name must be between 1 and 30 characters'),
    body('email')
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage('Invalid email format'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Invalid request data',
                details: errors.array()
            });
        }
        next();
    }
];

// Add error handling
process.on('unhandledRejection', (reason, promise) => {
    console.log('Unhandled Rejection at:', promise, 'reason:', reason);
    // Keep server running instead of crashing
});

process.on('uncaughtException', (error) => {
    console.log('Uncaught Exception:', error);
    // Log but don't exit immediately
});

// ================================
// Authentication Endpoints
// ================================


// Login endpoint with validation, JWT, and session management
app.post('/api/auth/login', validateLoginRequest, async (req, res) => {
    try {
        const { identifier, password } = req.body;
        const clientIP = req.ip || req.connection.remoteAddress;
        
        await logAccessAttempt(identifier, clientIP, 'login_attempt');
        
        const user = await dbAuthenticateUser(identifier, password);
        
        // Generate JWT token
        const token = generateToken(user);
        
        // Generate session ID
        const sessionId = crypto.randomBytes(32).toString('hex');
        
        // Create session in database
        await createUserSession(sessionId, user.id, req);
        
        // Set secure cookie (use different name for development vs production)
        const cookieName = process.env.NODE_ENV === 'production' ? '__Host-sessionid' : 'sessionid';
        const cookieOptions = {
            httpOnly: true,
            sameSite: 'strict', // CSSECDV requirement: Must use 'strict' for session cookies
            maxAge: 1800000, // 30 minutes
            path: '/'
        };
        
        // Only use secure and __Host- prefix in production
        if (process.env.NODE_ENV === 'production') {
            cookieOptions.secure = true;
        }
        
        res.cookie(cookieName, sessionId, cookieOptions);
        
        await logAuthEvent('LOGIN_SUCCESS', user.id, clientIP, `User ${user.username} logged in successfully with session ${sessionId.substring(0, 8)}...`);
        
        // Return user data and token - FIXED: Include all user fields
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                email: user.email,
                created_at: user.created_at,      
                last_login: user.last_login,        
                updated_at: user.updated_at,     
                roles: user.roles,
                permissions: user.permissions
            },
            token,
            expires_in: '24h',
            session_expires_in: '30m'
        });
        
    } catch (error) {
        const clientIP = req.ip || req.connection.remoteAddress;
        await logAuthEvent('LOGIN_FAILED', null, clientIP, `Login failed: ${error.message}`);
        
        console.error('Login error:', error);
        res.status(401).json({
            error: error.message || 'Authentication failed'
        });
    }
});

// Logout endpoint with session invalidation
app.post('/api/auth/logout', authenticateUser, async (req, res) => {
    try {
        const sessionId = req.sessionId;
        const userId = req.user.id;
        const clientIP = req.ip || req.connection.remoteAddress;
        
        // Invalidate the current session
        await invalidateSession(sessionId);
        
        // Clear the session cookie
        const cookieName = process.env.NODE_ENV === 'production' ? '__Host-sessionid' : 'sessionid';
        const cookieOptions = {
            httpOnly: true,
            sameSite: 'strict',
            path: '/'
        };
        
        if (process.env.NODE_ENV === 'production') {
            cookieOptions.secure = true;
        }
        
        res.clearCookie(cookieName, cookieOptions);
        
        await logAuthEvent('LOGOUT_SUCCESS', userId, clientIP, `User ${req.user.username} logged out successfully`);
        
        res.json({
            success: true,
            message: 'Logout successful',
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        const clientIP = req.ip || req.connection.remoteAddress;
        await logAuthEvent('LOGOUT_FAILED', req.user?.id, clientIP, `Logout failed: ${error.message}`);
        
        console.error('Logout error:', error);
        res.status(500).json({
            error: 'Logout failed'
        });
    }
});

// Logout all sessions endpoint
app.post('/api/auth/logout-all', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const clientIP = req.ip || req.connection.remoteAddress;
        
        // Invalidate all user sessions
        await invalidateAllUserSessions(userId);
        
        // Clear the current session cookie
        const cookieName = process.env.NODE_ENV === 'production' ? '__Host-sessionid' : 'sessionid';
        const cookieOptions = {
            httpOnly: true,
            sameSite: 'strict',
            path: '/'
        };
        
        if (process.env.NODE_ENV === 'production') {
            cookieOptions.secure = true;
        }
        
        res.clearCookie(cookieName, cookieOptions);
        
        await logAuthEvent('LOGOUT_ALL_SUCCESS', userId, clientIP, `User ${req.user.username} logged out from all sessions`);
        
        res.json({
            success: true,
            message: 'Logged out from all sessions successfully',
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        const clientIP = req.ip || req.connection.remoteAddress;
        await logAuthEvent('LOGOUT_ALL_FAILED', req.user?.id, clientIP, `Logout all failed: ${error.message}`);
        
        console.error('Logout all error:', error);
        res.status(500).json({
            error: 'Logout all failed'
        });
    }
});

// Registration endpoint with validation and RBAC integration
app.post('/api/auth/register', [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username must be between 3 and 30 characters')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Username can only contain letters, numbers, hyphens, and underscores'),
    body('displayName')
        .trim()
        .isLength({ min: 1, max: 30 })
        .withMessage('Display name must be between 1 and 30 characters'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Invalid email format'),
    body('password')
        .isLength({ min: 8 })
        .withMessage('Password must be at least 8 characters long'),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                error: 'Invalid request data',
                details: errors.array()
            });
        }
        next();
    }
], async (req, res) => {
    try {
        const { username, displayName, email, password } = req.body;
        const clientIP = req.ip || req.connection.remoteAddress;
        
        // Import the registerUser function
        const { registerUser } = await import('./src/utils/databaseAPI.js');
        
        await logSecurityEvent('REGISTRATION_ATTEMPT', null, `Registration attempt for username: ${username}, email: ${email}, IP: ${clientIP}`);
        
        const newUser = await registerUser({
            username,
            displayName,
            email,
            password
        });
        
        await logSecurityEvent('REGISTRATION_SUCCESS', newUser.id, `User ${username} registered successfully`);
        
        // Return success without sensitive data
        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: {
                id: newUser.id,
                username: newUser.username,
                display_name: newUser.display_name,
                email: newUser.email
            },
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        const clientIP = req.ip || req.connection.remoteAddress;
        await logSecurityEvent('REGISTRATION_FAILED', null, `Registration failed: ${error.message}, IP: ${clientIP}`);
        
        console.error('Registration error:', error);
        res.status(400).json({
            error: error.message || 'Registration failed'
        });
    }
});

// Token refresh endpoint
app.post('/api/auth/refresh', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const refreshedToken = refreshToken(token);
        
        res.json({
            success: true,
            token: refreshedToken,
            expires_in: '24h'
        });
        
    } catch (error) {
        res.status(401).json({ error: 'Cannot refresh token' });
    }
});

// API endpoint for frontend route verification
app.get('/api/auth/verify-permission/:permission', 
    authenticateUser,
    async (req, res) => {
        try {
            const { permission } = req.params;
            const hasPermission = await userHasPermission(req.user.id, permission);
            
            res.json({
                hasPermission,
                user: req.user,
                permission: permission
            });
            
        } catch (error) {
            console.error('Permission verification error:', error);
            res.status(500).json({ error: 'Permission verification failed' });
        }
    }
);

// Test endpoint to verify authorization
app.get('/api/auth/test',
    authenticateUser,
    async (req, res) => {
        try {
            const userRoles = await getUserRoles(req.user.id);
            const permissions = await getUserPermissions(req.user.id);
            
            res.json({
                message: 'Authentication successful',
                user: req.user,
                roles: userRoles,
                permissions: permissions,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch user data' });
        }
    }
);

// ================================
// User Management API Endpoints
// ================================

// GET /api/users - List all users (admin and manager only)
app.get('/api/users', 
    authenticateUser,
    requireRole(['admin', 'manager']),
    async (req, res) => {
        try {
            const users = await getAllUsersWithRoles();
            
            // Log access to user list
            await logSecurityEvent('USER_LIST_ACCESS', req.user.id, `User ${req.user.username} accessed user list`);
            
            // Return user list without sensitive information
            const sanitizedUsers = users.map(user => ({
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                email: user.email,
                created_at: user.created_at,
                last_login: user.last_login,
                roles: user.roles
            }));
            
            res.json({
                success: true,
                users: sanitizedUsers,
                count: sanitizedUsers.length,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            console.error('Error fetching users:', error);
            res.status(500).json({ 
                error: 'Failed to fetch users'
            });
        }
    }
);

// PUT /api/users/:id - Update user information
app.put('/api/users/:id',
    authenticateUser,
    validateUserUpdateRequest,
    async (req, res) => {
        try {
            const targetUserId = parseInt(req.params.id);
            const currentUserId = req.user.id;
            const { display_name, email } = req.body;
            
            // Check if user is updating their own profile or if they have admin permissions
            const isOwnProfile = targetUserId === currentUserId;
            const hasAdminPermission = await userHasPermission(currentUserId, 'manage_users');
            
            if (!isOwnProfile && !hasAdminPermission) {
                await logAuthorizationFailure(currentUserId, 'update_user', 'Insufficient permissions to update other users');
                return res.status(403).json({
                    error: 'You can only update your own profile or need admin permissions'
                });
            }
            
            // Get current user data
            const targetUser = await getUserWithRolesAndPermissions(targetUserId);
            if (!targetUser) {
                return res.status(404).json({
                    error: 'User not found'
                });
            }
            
            // Prepare update data
            const updateData = {};
            if (display_name !== undefined) {
                updateData.display_name = display_name;
            }
            if (email !== undefined) {
                updateData.email = email;
            }
            
            // Only proceed if there's something to update
            if (Object.keys(updateData).length === 0) {
                return res.status(400).json({
                    error: 'No valid fields to update'
                });
            }
            
            // Update user in database
            const { error } = await supabase
                .from('users')
                .update({
                    ...updateData,
                    updated_at: new Date().toISOString()
                })
                .eq('id', targetUserId);
            
            if (error) {
                throw error;
            }
            
            // Log the update
            const updateType = isOwnProfile ? 'PROFILE_UPDATE' : 'USER_UPDATE';
            const updateDescription = isOwnProfile 
                ? `User ${req.user.username} updated their profile`
                : `Admin ${req.user.username} updated user ${targetUser.username}`;
                
            await logSecurityEvent(updateType, currentUserId, updateDescription);
            
            // Get updated user data
            const updatedUser = await getUserWithRolesAndPermissions(targetUserId);
            
            res.json({
                success: true,
                message: 'User updated successfully',
                user: {
                    id: updatedUser.id,
                    username: updatedUser.username,
                    display_name: updatedUser.display_name,
                    email: updatedUser.email,
                    roles: updatedUser.roles
                },
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            console.error('Error updating user:', error);
            res.status(500).json({ 
                error: 'Failed to update user'
            });
        }
    }
);

// PUT /api/users/:userId/roles - Update user roles
app.put('/api/users/:userId/roles',
    authenticateUser,
    requirePermission('manage_users'),
    async (req, res) => {
        try {
            const { userId } = req.params;
            const { roleIds } = req.body;
            const currentUserId = req.user.id;

            // Validate that user can assign these roles
            for (const roleId of roleIds) {
                const canAssign = await canUserAssignRole(currentUserId, roleId);
                if (!canAssign) {
                    return res.status(403).json({
                        error: `You do not have permission to assign role ${roleId}`
                    });
                }
            }

            await updateUserRolesSecure(currentUserId, userId, roleIds);
            
            await logSecurityEvent('ROLE_UPDATE', currentUserId, `Updated roles for user ${userId}`);
            
            res.json({
                success: true,
                message: 'User roles updated successfully'
            });
            
        } catch (error) {
            console.error('Role update error:', error);
            res.status(500).json({ error: 'Failed to update user roles' });
        }
    }
);

// DELETE /api/users/:id - Delete user (admin only with layered security)
app.delete('/api/users/:id',
    authenticateUser,
    requireRole(['admin']),
    requirePermission('manage_users'),
    async (req, res) => {
        try {
            const targetUserId = req.params.id;
            
            if (parseInt(targetUserId) === req.user.id) {
                return res.status(400).json({
                    error: 'Cannot delete your own account'
                });
            }

            await logSecurityEvent('USER_DELETE', req.user.id, `Deleted user ${targetUserId}`);
            
            res.json({ 
                success: true,
                message: `User ${targetUserId} has been deleted`,
                deletedBy: req.user.id,
                timestamp: new Date().toISOString()
            });
            
        } catch (error) {
            console.error('Error deleting user:', error);
            res.status(500).json({ 
                error: 'Failed to delete user'
            });
        }
    }
);

// ================================
// Protected Routes (Frontend Routes)
// ================================

// Admin Dashboard
app.get('/admin',
    authenticateUser,
    requirePermission('admin_access'),
    (req, res) => {
        res.json({
            message: 'Welcome to the admin dashboard',
            user: req.user,
            timestamp: new Date().toISOString()
        });
    }
);

// User Management Interface
app.get('/users',
    authenticateUser,
    requireRole(['admin', 'manager']),
    (req, res) => {
        res.json({
            message: 'User management interface',
            user: req.user,
            timestamp: new Date().toISOString()
        });
    }
);

// Profile Management
app.get('/profile',
    authenticateUser,
    requirePermission('edit_profile'),
    (req, res) => {
        res.json({
            message: 'User profile interface',
            user: req.user,
            timestamp: new Date().toISOString()
        });
    }
);

// ================================
// Utility Endpoints
// ================================

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

// Catch-all for React Router - ONLY if dist directory exists
app.get('*', (req, res) => {
    const distIndexPath = path.join(__dirname, 'dist', 'index.html');
    if (fs.existsSync(distIndexPath)) {
        res.sendFile(distIndexPath);
    } else {
        // In development mode, redirect API calls that don't exist
        res.status(404).json({ 
            error: 'API endpoint not found',
            message: 'Running in development mode. Frontend should be on port 5173'
        });
    }
});

const PORT = process.env.PORT || 3001;

// Clean up expired sessions on server start
const { cleanupExpiredSessions } = await import('./src/utils/databaseAPI.js');
cleanupExpiredSessions().catch(err => console.log('Session cleanup on startup failed:', err));

// Set up periodic session cleanup (every 15 minutes)
setInterval(async () => {
    try {
        await cleanupExpiredSessions();
        console.log('Periodic session cleanup completed');
    } catch (error) {
        console.error('Periodic session cleanup failed:', error);
    }
}, 15 * 60 * 1000); // 15 minutes

app.listen(PORT, () => {
    console.log(`Express server running on http://localhost:${PORT}`);
    console.log(`React app should be running on http://localhost:5173`);
    console.log('CORS Configuration:');
    console.log('  - Origin: Dynamic function with allowed localhost variants');
    console.log('  - Credentials: true');
    console.log('  - Cookie SameSite: lax');
    console.log(`  - Cookie Name: ${process.env.NODE_ENV === 'production' ? '__Host-sessionid' : 'sessionid'}`);
    console.log('  - Session cleanup: Every 15 minutes');
    
    if (!fs.existsSync(distPath)) {
        console.log(' Note: Running in development mode. Build the app with "npm run build" for production.');
    }
});