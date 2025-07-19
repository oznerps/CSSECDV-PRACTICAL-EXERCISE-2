// Authorization utility functions for server-side verification

export const verifyPermissionServer = async (permission, token) => {
    try {
        const response = await fetch(`http://localhost:3001/api/auth/verify-permission/${permission}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        return response.ok;
    } catch (error) {
        console.error('Permission verification failed:', error);
        return false;
    }
};

export const verifyRoleServer = async (role, token) => {
    try {
        const response = await fetch(`http://localhost:3001/api/auth/test`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            return false;
        }
        
        const data = await response.json();
        const userRoles = data.roles || [];
        
        return userRoles.some(userRole => userRole.name === role);
    } catch (error) {
        console.error('Role verification failed:', error);
        return false;
    }
};

// Additional utility functions
export const getUserPermissions = async (token) => {
    try {
        const response = await fetch('http://localhost:3001/api/auth/test', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            return [];
        }
        
        const data = await response.json();
        return data.permissions || [];
    } catch (error) {
        console.error('Failed to get user permissions:', error);
        return [];
    }
};

export const getUserRoles = async (token) => {
    try {
        const response = await fetch('http://localhost:3001/api/auth/test', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) {
            return [];
        }
        
        const data = await response.json();
        return data.roles || [];
    } catch (error) {
        console.error('Failed to get user roles:', error);
        return [];
    }
};