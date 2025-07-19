const express = require('express');
const cors = require('cors');
const path = require('path');

// Import your existing database functions
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

// Authentication middleware
const authenticateUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                error: 'Authentication required'
            });
        }

        const token = authHeader.split(' ')[1];
        const userId = parseInt(token);
        
        if (!userId || isNaN(userId)) {
            return res.status(401).json({ 
                error: 'Invalid authentication token'
            });
        }

        req.user = { id: userId };
        next();
        
    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(500).json({ 
            error: 'Authentication check failed'
        });
    }
};

// C1 IMPLEMENTATION: Authorization Middleware
const requireRole = (allowedRoles) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({ 
                    error: 'Authentication required'
                });
            }

            const userRoles = await getUserRoles(req.user.id);
            const hasRequiredRole = userRoles.some(role => 
                allowedRoles.includes(role.name)
            );

            if (!hasRequiredRole) {
                return res.status(403).json({ 
                    error: 'Insufficient permissions'
                });
            }

            next();
            
        } catch (error) {
            console.error('Role authorization error:', error);
            return res.status(500).json({ 
                error: 'Authorization check failed'
            });
        }
    };
};

const requirePermission = (requiredPermission) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({ 
                    error: 'Authentication required'
                });
            }

            const hasPermission = await userHasPermission(req.user.id, requiredPermission);

            if (!hasPermission) {
                return res.status(403).json({ 
                    error: 'Insufficient permissions'
                });
            }

            next();
            
        } catch (error) {
            console.error('Permission authorization error:', error);
            return res.status(500).json({ 
                error: 'Permission check failed'
            });
        }
    };
};

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