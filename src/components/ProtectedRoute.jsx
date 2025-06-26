import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
    const [isAuthenticated, setIsAuthenticated] = useState(null); // null = loading, true/false = determined
    
    useEffect(() => {
        const checkAuthentication = () => {
            try {
                const userData = localStorage.getItem('currentUser');
                if (userData) {
                    const user = JSON.parse(userData);
                    setIsAuthenticated(true);
                } else {
                    setIsAuthenticated(false);
                }
            } catch (error) {
                // If there's an error parsing the user data, consider them not authenticated
                localStorage.removeItem('currentUser');
                setIsAuthenticated(false);
            }
        };
        
        checkAuthentication();
    }, []);
    
    // Show loading state while checking authentication
    if (isAuthenticated === null) {
        return (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '200px' }}>
                <p>Loading...</p>
            </div>
        );
    }
    
    // Redirect to login if not authenticated
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }
    
    // return children if authenticated
    return children;
};

export default ProtectedRoute;