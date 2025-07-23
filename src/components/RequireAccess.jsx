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
    requireAll = false,
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

    if (loading) {
        return <LoadingSpinner message="Validating access..." />;
    }

    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    const roleRequirements = [
        ...(requiredRole ? [requiredRole] : []),
        ...requiredRoles
    ];
    
    const permissionRequirements = [
        ...(requiredPermission ? [requiredPermission] : []),
        ...requiredPermissions
    ];

    if (roleRequirements.length > 0) {
        const hasRequiredRoles = requireAll 
            ? roleRequirements.every(role => hasRole(role))
            : hasAnyRole(roleRequirements);
            
        if (!hasRequiredRoles) {
            const redirectPath = redirectToLogin ? '/login' : fallbackPath;
            return <Navigate to={redirectPath} replace />;
        }
    }

    if (permissionRequirements.length > 0) {
        const hasRequiredPermissions = requireAll
            ? permissionRequirements.every(permission => hasPermission(permission))
            : hasAnyPermission(permissionRequirements);
            
        if (!hasRequiredPermissions) {
            const redirectPath = redirectToLogin ? '/login' : fallbackPath;
            return <Navigate to={redirectPath} replace />;
        }
    }

    return children;
};

export default RequireAccess;