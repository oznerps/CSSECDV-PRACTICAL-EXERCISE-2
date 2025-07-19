import { verifyToken } from './src/utils/jwtUtils.js'
import { generateToken } from './src/utils/jwtUtils.js';
import { authenticateUser as dbAuthenticateUser } from './src/utils/databaseAPI.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { body, validationResult } from 'express-validator';
import { generateToken } from './src/utils/jwtUtils.js';
import { authenticateUser as dbAuthenticateUser } from './src/utils/databaseAPI.js';

const express = require('express');
const cors = require('cors');
const path = require('path');

// Import JWT utilities
const { verifyToken } = require('./src/utils/jwtUtils.js');

const { 
    getUserRoles, 
    userHasPermission,
    getUserPermissions 
} = require('./src/utils/databaseAPI.js');

const app = express();

// Middleware configuration
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true
}));
app.use(express.static(path.join(__dirname, 'dist')));

// Updated JWT Authentication middleware

const authenticateUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                error: 'Authentication required',
                code: 'MISSING_TOKEN'
            });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify JWT token instead of parsing userId
        const decoded = verifyToken(token);
        
        // Attach user info from token
        req.user = {
            id: decoded.userId,
            username: decoded.username,
            email: decoded.email,
            roles: decoded.roles
        };
        
        next();
        
    } catch (error) {
        console.error('Authentication error:', error.message);
        
        if (error.message.includes('expired')) {
            return res.status(401).json({ 
                error: 'Token expired',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        return res.status(401).json({ 
            error: 'Invalid authentication token',
            code: 'INVALID_TOKEN'
        });
    }
};

// Login endpoint that returns JWT
app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body;
        
        if (!identifier || !password) {
            return res.status(400).json({
                error: 'Username/email and password are required'
            });
        }
        
        // Use existing database authentication
        const user = await dbAuthenticateUser(identifier, password);
        
        // Generate JWT token
        const token = generateToken(user);
        
        // Return user data and token
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                email: user.email,
                roles: user.roles,
                permissions: user.permissions
            },
            token,
            expires_in: '24h'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({
            error: error.message || 'Authentication failed'
        });
    }
});

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
    crossOriginEmbedderPolicy: false // Allow for development
}));

// Apply rate limiting
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

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


app.post('/api/auth/login', validateLoginRequest, async (req, res) => {
    try {
        const { identifier, password } = req.body;
        
        if (!identifier || !password) {
            return res.status(400).json({
                error: 'Username/email and password are required'
            });
        }
        
        const user = await dbAuthenticateUser(identifier, password);
        
        // Generate JWT token
        const token = generateToken(user);
        
        // Return user data and token
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                email: user.email,
                roles: user.roles,
                permissions: user.permissions
            },
            token,
            expires_in: '24h'
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(401).json({
            error: error.message || 'Authentication failed'
        });
    }
});

// C2 IMPLEMENTATION: Protected Routes

// Admin Dashboard - requires 'admin_access' permission
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

// User Management - requires admin or manager role
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

// Profile Management - requires edit_profile permission
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

// API endpoint with layered security - requires admin role AND manage_users permission
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

            // Simulate user deletion
            console.log(`Admin user ${req.user.id} deleted user ${targetUserId}`);
            
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

// Test endpoint to verify authorization
app.get('/auth/test',
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

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
});

// Catch-all for React Router
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Express server running on http://localhost:${PORT}`);
    console.log(`React app should be running on http://localhost:5173`);
});