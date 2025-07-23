import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import LoadingSpinner from './LoadingSpinner';

const RequireAccess = ({ 
    children, 
    requiredRole = null,
    requiredPermission = null,
    requiredRoles = [],
    requiredPermissions = [],
    requireAll = false, // true = must have ALL roles/permissions, false = must have ANY
    fallbackPath = '/unauthorized',
    redirectToLogin = false
}) => {
    const { 
        isAuthenticated, 
        loading, 
        hasRole, 
        hasPermission, 
        hasAnyRole, 
        hasAnyPermission 
    } = useAuth();

    // Show loading while checking authentication
    if (loading) {
        return <LoadingSpinner message="Validating access..." />;
    }

    // Redirect to login if not authenticated
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    // Build requirements arrays
    const roleRequirements = [
        ...(requiredRole ? [requiredRole] : []),
        ...requiredRoles
    ];
    
    const permissionRequirements = [
        ...(requiredPermission ? [requiredPermission] : []),
        ...requiredPermissions
    ];

    // Check role requirements
    if (roleRequirements.length > 0) {
        const hasRequiredRoles = requireAll 
            ? roleRequirements.every(role => hasRole(role))
            : hasAnyRole(roleRequirements);
            
        if (!hasRequiredRoles) {
            const redirectPath = redirectToLogin ? '/login' : fallbackPath;
            return <Navigate to={redirectPath} replace />;
        }
    }

    // Check permission requirements
    if (permissionRequirements.length > 0) {
        const hasRequiredPermissions = requireAll
            ? permissionRequirements.every(permission => hasPermission(permission))
            : hasAnyPermission(permissionRequirements);
            
        if (!hasRequiredPermissions) {
            const redirectPath = redirectToLogin ? '/login' : fallbackPath;
            return <Navigate to={redirectPath} replace />;
        }
    }

    // All requirements met
    return children;
};

export default RequireAccess;