import { useState, useEffect, useCallback } from 'react';
import { getSession, clearSession, isAuthenticated } from '../utils/SessionManager';
import { authAPI } from '../utils/apiInterceptor';
import { useSessionTimeout } from '../contexts/SessionTimeoutContext';

export const useAuth = () => {
    const { isAuthenticated: contextAuth, handleForceLogout } = useSessionTimeout();
    const [authState, setAuthState] = useState({
        user: null,
        permissions: [],
        isAuthenticated: false,
        loading: true,
        error: null
    });

    const checkSession = useCallback(async (skipServerValidation = false) => {
        try {
            // Check client-side session data
            const sessionUser = getSession();
            const hasClientSession = contextAuth && isAuthenticated() && sessionUser;
            
            if (!hasClientSession) {
                setAuthState(prev => ({ ...prev, isAuthenticated: false, loading: false }));
                return;
            }

            // Skip server validation when requested
            if (skipServerValidation) {
                setAuthState({
                    user: sessionUser,
                    permissions: sessionUser.permissions || [],
                    isAuthenticated: true,
                    loading: false,
                    error: null
                });
                return;
            }

            // Server validation for session tampering detection
            try {
                console.log('Validating session with server...');
                const response = await authAPI.test();
                console.log('Server validation successful');
                setAuthState({
                    user: sessionUser,
                    permissions: response.permissions || [],
                    isAuthenticated: true,
                    loading: false,
                    error: null
                });
            } catch (apiError) {
                console.error('Server session validation failed:', apiError);
                
                // Use cached data if rate limited
                if (apiError.message.includes('429') || apiError.message.includes('Too Many Requests')) {
                    console.warn('Rate limited, using cached session data');
                    setAuthState({
                        user: sessionUser,
                        permissions: sessionUser.permissions || [],
                        isAuthenticated: true,
                        loading: false,
                        error: null
                    });
                    return;
                }

                // Logout on session validation failure
                console.log('Session validation failed, triggering logout');
                handleForceLogout();
                setAuthState({
                    user: null,
                    permissions: [],
                    isAuthenticated: false,
                    loading: false,
                    error: 'Session validation failed'
                });
            }
        } catch (error) {
            console.error('Session check error:', error);
            setAuthState({
                user: null,
                permissions: [],
                isAuthenticated: false,
                loading: false,
                error: error.message
            });
        }
    }, [contextAuth, handleForceLogout]);

    // Role checking utilities
    const hasRole = useCallback((roleName) => {
        if (!authState.user || !authState.user.roles) return false;
        return authState.user.roles.some(role => 
            typeof role === 'string' ? role === roleName : role.name === roleName
        );
    }, [authState.user]);

    const hasPermission = useCallback((permissionName) => {
        return authState.permissions.includes(permissionName);
    }, [authState.permissions]);

    const hasAnyRole = useCallback((roleNames) => {
        return roleNames.some(role => hasRole(role));
    }, [hasRole]);

    const hasAnyPermission = useCallback((permissionNames) => {
        return permissionNames.some(permission => hasPermission(permission));
    }, [hasPermission]);

    const getUserRoles = useCallback(() => {
        if (!authState.user || !authState.user.roles) return [];
        return Array.isArray(authState.user.roles) ? authState.user.roles.map(role => 
            typeof role === 'string' ? role : role.name
        ) : [];
    }, [authState.user]);

    const getRoleLevel = useCallback(() => {
        if (hasRole('admin')) return 'admin';
        if (hasRole('manager')) return 'manager';
        return 'user';
    }, [hasRole]);

    // Initialize with balanced validation approach
    useEffect(() => {
        checkSession(true); // Skip server validation to prevent timeouts
    }, [checkSession]);

    // React to authentication context changes
    useEffect(() => {
        if (!contextAuth) {
            setAuthState({
                user: null,
                permissions: [],
                isAuthenticated: false,
                loading: false,
                error: null
            });
        }
    }, [contextAuth]);

    return {
        ...authState,
        checkSession,
        hasRole,
        hasPermission,
        hasAnyRole,
        hasAnyPermission,
        getUserRoles,
        getRoleLevel
    };
};