import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { getSession } from '../utils/sessionmanager';
import { userHasPermission } from '../utils/databaseAPI';

const RequirePermission = ({ children, requiredPermission, fallbackPath = '/unauthorized' }) => {
    // State to track permission checking process
    const [hasPermission, setHasPermission] = useState(null); // null = checking, true = allowed, false = denied
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const checkPermission = async () => {
            try {
                setIsLoading(true);
                setError(null);
                
                // First, verify the user is authenticated
                const user = getSession();
                if (!user || !user.id) {
                    setHasPermission(false);
                    setIsLoading(false);
                    return;
                }

                // Check if user has the specific permission
                const permissionGranted = await userHasPermission(user.id, requiredPermission);
                setHasPermission(permissionGranted);
                
            } catch (error) {
                console.error('Permission check failed:', error);
                setError('Unable to verify permissions');
                setHasPermission(false); // Fail secure - deny access on error
            } finally {
                setIsLoading(false);
            }
        };

        checkPermission();
    }, [requiredPermission]); // Re-check if required permission changes

    // Show loading state while checking permissions
    if (isLoading) {
        return (
            <div style={{ 
                textAlign: 'center', 
                marginTop: '2rem',
                padding: '1rem'
            }}>
                <p>Verifying permissions...</p>
            </div>
        );
    }

    // Show error state if permission check failed
    if (error) {
        return (
            <div style={{ 
                textAlign: 'center', 
                marginTop: '2rem',
                padding: '1rem',
                color: '#e74c3c'
            }}>
                <p>{error}</p>
                <p>Please try refreshing the page or contact support if the problem persists.</p>
            </div>
        );
    }

    // Redirect if permission denied
    if (hasPermission === false) {
        const user = getSession();
        // If user is not authenticated, send to login; otherwise send to unauthorized page
        return user ? <Navigate to={fallbackPath} replace /> : <Navigate to="/login" replace />;
    }

    // Permission granted - render the protected content
    return children;
};

export default RequirePermission;