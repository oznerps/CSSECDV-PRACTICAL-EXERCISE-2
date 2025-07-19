import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { getSession } from '../utils/sessionmanager';
import { userHasPermission } from '../utils/databaseAPI';

// Shared authorization hook 
const useAuthorization = (authCheck) => {
    const [isAuthorized, setIsAuthorized] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const checkAuth = async () => {
            try {
                setIsLoading(true);
                setError(null);
                
                const user = getSession();
                if (!user?.id) {
                    setIsAuthorized(false);
                    return;
                }

                const result = await authCheck(user.id);
                setIsAuthorized(result);
                
            } catch (error) {
                console.error('Authorization failed:', error);
                setError('Unable to verify permissions');
                setIsAuthorized(false);
            } finally {
                setIsLoading(false);
            }
        };

        checkAuth();
    }, [authCheck]);

    return { isAuthorized, isLoading, error };
};

const RequirePermission = ({ children, requiredPermission, fallbackPath = '/unauthorized' }) => {
    const authCheck = React.useCallback(
        (userId) => userHasPermission(userId, requiredPermission),
        [requiredPermission]
    );
    
    const { isAuthorized, isLoading, error } = useAuthorization(authCheck);

    if (isLoading) {
        return <div style={{ textAlign: 'center', marginTop: '2rem' }}>Verifying permissions...</div>;
    }

    if (error) {
        return <div style={{ textAlign: 'center', marginTop: '2rem', color: '#e74c3c' }}>{error}</div>;
    }

    if (!isAuthorized) {
        const user = getSession();
        return user ? <Navigate to={fallbackPath} replace /> : <Navigate to="/login" replace />;
    }

    return children;
};

export default RequirePermission;