import React, { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import PropTypes from 'prop-types';
import { getSession, getAuthToken } from '../utils/SessionManager';
import { verifyPermissionServer } from '../utils/authorizationUtils';

const RequirePermission = ({ children, requiredPermission, fallbackPath = '/unauthorized' }) => {
    const [isAuthorized, setIsAuthorized] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const checkPermission = async () => {
            try {
                setIsLoading(true);
                setError(null);
                
                const user = getSession();
                const token = getAuthToken();
                
                if (!user?.id || !token) {
                    setIsAuthorized(false);
                    return;
                }

                // Server-side permission verification
                const hasPermission = await verifyPermissionServer(requiredPermission, token);
                setIsAuthorized(hasPermission);
                
            } catch (error) {
                console.error('Permission verification failed:', error);
                setError('Unable to verify permissions');
                setIsAuthorized(false);
            } finally {
                setIsLoading(false);
            }
        };

        checkPermission();
    }, [requiredPermission]);

    if (isLoading) {
        return (
            <div style={{ 
                textAlign: 'center', 
                marginTop: '2rem',
                padding: '2rem',
                backgroundColor: '#f8f9fa',
                borderRadius: '8px',
                border: '1px solid #dee2e6'
            }}>
                <div style={{ marginBottom: '1rem' }}>🔍</div>
                <div>Verifying permissions...</div>
                <div style={{ fontSize: '0.9rem', color: '#6c757d', marginTop: '0.5rem' }}>
                    Checking access to {requiredPermission}
                </div>
            </div>
        );
    }

    if (error) {
        return (
            <div style={{ 
                textAlign: 'center', 
                marginTop: '2rem',
                padding: '2rem',
                backgroundColor: '#f8d7da',
                borderRadius: '8px',
                border: '1px solid #f5c6cb',
                color: '#721c24'
            }}>
                <div style={{ marginBottom: '1rem' }}>⚠️</div>
                <div>{error}</div>
                <div style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>
                    Please try refreshing the page
                </div>
            </div>
        );
    }

    if (!isAuthorized) {
        const user = getSession();
        return user ? <Navigate to={fallbackPath} replace /> : <Navigate to="/login" replace />;
    }

    return children;
};

// PropTypes validation
RequirePermission.propTypes = {
    children: PropTypes.node.isRequired,
    requiredPermission: PropTypes.string.isRequired,
    fallbackPath: PropTypes.string
};

// Default props
RequirePermission.defaultProps = {
    fallbackPath: '/unauthorized'
};

export default RequirePermission;