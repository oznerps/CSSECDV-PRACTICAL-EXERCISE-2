import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { getSession } from '../utils/sessionmanager';
import { userHasPermission } from '../utils/databaseAPI';

const ProtectedRoute = ({ 
    children, 
    allowedRoles, 
    requiredPermissions = [], // New: array of permissions that must ALL be present
    requireAll = true, // New: whether user needs ALL permissions or just ONE
    fallbackPath = '/unauthorized' 
}) => {
    const [isAuthorized, setIsAuthorized] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const checkAuthorization = async () => {
            try {
                setIsLoading(true);
                setError(null);

                const user = getSession();

                if (!user) {
                    setIsAuthorized(false);
                    setIsLoading(false);
                    return;
                }

                // Step 1: Check role-based authorization (existing logic)
                let roleAuthorized = true;
                if (allowedRoles && allowedRoles.length > 0) {
                    const userRoles = Array.isArray(user.roles) ? user.roles : [user.role];
                    roleAuthorized = userRoles.some(role => allowedRoles.includes(role));
                }

                // Step 2: Check permission-based authorization (new logic)
                let permissionAuthorized = true;
                if (requiredPermissions.length > 0) {
                    // Check each required permission
                    const permissionChecks = await Promise.all(
                        requiredPermissions.map(permission => 
                            userHasPermission(user.id, permission)
                        )
                    );

                    if (requireAll) {
                        // User must have ALL permissions
                        permissionAuthorized = permissionChecks.every(hasPermission => hasPermission);
                    } else {
                        // User must have at least ONE permission
                        permissionAuthorized = permissionChecks.some(hasPermission => hasPermission);
                    }
                }

                // Step 3: Combine role and permission authorization
                const finalAuthorization = roleAuthorized && permissionAuthorized;
                setIsAuthorized(finalAuthorization);

            } catch (error) {
                console.error('Authorization check failed:', error);
                setError('Unable to verify authorization');
                setIsAuthorized(false); // Fail secure
            } finally {
                setIsLoading(false);
            }
        };

        checkAuthorization();
    }, [allowedRoles, requiredPermissions, requireAll]);

    // Loading state
    if (isLoading) {
        return <p style={{ textAlign: 'center', marginTop: '2rem' }}>Verifying access...</p>;
    }

    // Error state
    if (error) {
        return (
            <div style={{ textAlign: 'center', marginTop: '2rem', color: '#e74c3c' }}>
                <p>{error}</p>
            </div>
        );
    }

    // Authorization check result
    if (!isAuthorized) {
        const user = getSession();
        return user ? <Navigate to={fallbackPath} replace /> : <Navigate to="/login" replace />;
    }

    return children;
};

export default ProtectedRoute;