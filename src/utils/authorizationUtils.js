import {getAuthToken, clearSession } from './SessionManager';

// Make authenticated API request
const makeAuthRequest = async (url, options = {}) => {
    const token = getAuthToken();
    
    if (!token) {
        throw new Error('No authentication token available');
    }
    
    const defaultOptions = {
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers,
        },
    };
    
    const response = await fetch(url, {
        ...defaultOptions,
        ...options,
    });
    
    // Handle token expiration
    if (response.status === 401) {
        const data = await response.json();
        if (data.code === 'TOKEN_EXPIRED' || data.code === 'INVALID_TOKEN') {
            clearSession();
            window.location.href = '/login';
            return;
        }
    }
    
    return response;
};

// Verify permission on server
export const verifyPermissionServer = async (permission, token = null) => {
    try {
        const authToken = token || getAuthToken();
        
        if (!authToken) {
            console.warn('No auth token available for permission check');
            return false;
        }
        
        const response = await fetch(`http://localhost:3001/api/auth/verify-permission/${permission}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${authToken}`,
                'Content-Type': 'application/json',
            },
        });
        
        if (!response.ok) {
            if (response.status === 401) {
                // Token expired or invalid
                clearSession();
                return false;
            }
            if (response.status === 403) {
                // Permission denied
                return false;
            }
            throw new Error(`Permission check failed: ${response.status}`);
        }
        
        const data = await response.json();
        return data.hasPermission === true;
        
    } catch (error) {
        console.error('Error verifying permission:', error);
        return false;
    }
};

// Check multiple permissions
export const verifyMultiplePermissions = async (permissions) => {
    try {
        const results = await Promise.all(
            permissions.map(permission => verifyPermissionServer(permission))
        );
        
        return permissions.reduce((acc, permission, index) => {
            acc[permission] = results[index];
            return acc;
        }, {});
        
    } catch (error) {
        console.error('Error verifying multiple permissions:', error);
        return permissions.reduce((acc, permission) => {
            acc[permission] = false;
            return acc;
        }, {});
    }
};

// Update user roles (admin function)
export const updateUserRoles = async (userId, roleIds) => {
    try {
        const response = await makeAuthRequest(`http://localhost:3001/api/users/${userId}/roles`, {
            method: 'PUT',
            body: JSON.stringify({ roleIds }),
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Failed to update user roles');
        }
        
        return await response.json();
        
    } catch (error) {
        console.error('Error updating user roles:', error);
        throw error;
    }
};

// Get current user's permissions from server
export const getCurrentUserPermissions = async () => {
    try {
        const response = await makeAuthRequest('http://localhost:3001/api/auth/test');
        
        if (!response.ok) {
            throw new Error('Failed to fetch user permissions');
        }
        
        const data = await response.json();
        return data.permissions || [];
        
    } catch (error) {
        console.error('Error fetching user permissions:', error);
        return [];
    }
};

// Check if current user has role
export const currentUserHasRole = async (roleName) => {
    try {
        const response = await makeAuthRequest('http://localhost:3001/api/auth/test');
        
        if (!response.ok) {
            return false;
        }
        
        const data = await response.json();
        const userRoles = data.roles || [];
        
        return userRoles.some(role => role.name === roleName);
        
    } catch (error) {
        console.error('Error checking user role:', error);
        return false;
    }
};

// Logout and clear session
export const logout = async () => {
    try {
        clearSession();
        window.location.href = '/login';
    } catch (error) {
        console.error('Error during logout:', error);
        clearSession();
        window.location.href = '/login';
    }
};