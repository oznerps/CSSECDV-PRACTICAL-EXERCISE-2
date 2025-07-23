import { Navigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { isAuthenticated as checkAuthStatus } from '../utils/SessionManager';
import LoadingSpinner from './LoadingSpinner';

const SmartRedirect = () => {
    const { isAuthenticated, loading } = useAuth();
    
    // Double-check authentication status to prevent redirect loops
    const hasValidSession = checkAuthStatus();

    if (loading) {
        return <LoadingSpinner message="Loading..." />;
    }

    // Use both hook state and direct session check for reliability
    const userIsAuthenticated = isAuthenticated || hasValidSession;
    
    // Redirect authenticated users to home, others to login
    return <Navigate to={userIsAuthenticated ? "/home" : "/login"} replace />;
};

export default SmartRedirect;