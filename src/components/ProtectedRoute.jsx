import { Navigate } from 'react-router-dom';
import { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import { useAuth } from '../hooks/useAuth';
import { authAPI } from '../utils/apiInterceptor';
import LoadingSpinner from './LoadingSpinner';

const ProtectedRoute = ({ children, fallbackPath = '/unauthorized' }) => {
    const { isAuthenticated, loading } = useAuth();
    const [hasServerValidated, setHasServerValidated] = useState(false);
    const [isValidating, setIsValidating] = useState(false);
    
    // Server validation on first route access
    useEffect(() => {
        const validateWithServer = async () => {
            if (!isAuthenticated || hasServerValidated || loading) return;
            
            setIsValidating(true);
            try {
                console.log('ProtectedRoute: Validating session with server...');
                await authAPI.test();
                console.log('ProtectedRoute: Server validation successful');
                setHasServerValidated(true);
            } catch (error) {
                console.error('ProtectedRoute: Server validation failed:', error);
                // API interceptor handles 401 errors
            } finally {
                setIsValidating(false);
            }
        };
        
        validateWithServer();
    }, [isAuthenticated, hasServerValidated, loading]);
    
    // Show loading during validation
    if (loading || (isAuthenticated && !hasServerValidated && isValidating)) {
        return <LoadingSpinner message="Validating session..." />;
    }
    
    // Redirect unauthenticated users
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    return children;
};

ProtectedRoute.propTypes = {
    children: PropTypes.node.isRequired,
    fallbackPath: PropTypes.string
};

export default ProtectedRoute;