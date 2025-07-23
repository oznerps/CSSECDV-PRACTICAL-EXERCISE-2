import { useState, useEffect } from 'react';
import { getSession } from '../utils/SessionManager';
import { authAPI } from '../utils/apiInterceptor';

export const usePermissions = () => {
    const [user, setUser] = useState(null);
    const [permissions, setPermissions] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const loadUserData = async () => {
            try {
                const sessionUser = getSession();
                if (!sessionUser) {
                    setError('No session found');
                    return;
                }

                setUser(sessionUser);
                
                // Get fresh permissions from server
                try {
                    const response = await authAPI.test();
                    setPermissions(response.permissions || []);
                } catch (apiError) {
                    console.warn('Failed to fetch fresh permissions, using cached');
                    setPermissions(sessionUser.permissions || []);
                }
            } catch (err) {
                console.error('Error loading user data:', err);
                setError(err.message);
            } finally {
                setLoading(false);
            }
        };

        loadUserData();
    }, []);

    const hasRole = (roleName) => {
        if (!user || !user.roles) return false;
        return user.roles.some(role => 
            typeof role === 'string' ? role === roleName : role.name === roleName
        );
    };

    const hasPermission = (permissionName) => {
        return permissions.includes(permissionName);
    };

    const hasAnyRole = (roleNames) => {
        return roleNames.some(role => hasRole(role));
    };

    const hasAnyPermission = (permissionNames) => {
        return permissionNames.some(permission => hasPermission(permission));
    };

    const getUserRoles = () => {
        if (!user || !user.roles) return [];
        return Array.isArray(user.roles) ? user.roles.map(role => 
            typeof role === 'string' ? role : role.name
        ) : [];
    };

    const getRoleLevel = () => {
        if (hasRole('admin')) return 'admin';
        if (hasRole('manager')) return 'manager';
        return 'user';
    };

    return {
        user,
        permissions,
        loading,
        error,
        hasRole,
        hasPermission,
        hasAnyRole,
        hasAnyPermission,
        getUserRoles,
        getRoleLevel
    };
};