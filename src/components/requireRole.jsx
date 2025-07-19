import React, { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import PropTypes from 'prop-types';
import { getSession, getAuthToken } from '../utils/SessionManager';
import { verifyRoleServer } from '../utils/authorizationUtils';

const RequireRole = ({ children, requiredRole, fallbackPath = '/unauthorized' }) => {
    const [isAuthorized, setIsAuthorized] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const checkRole = async () => {
            try {
                setIsLoading(true);
                setError(null);
                
                const user = getSession();
                const token = getAuthToken();
                
                if (!user?.id || !token) {
                    setIsAuthorized(false);
                    return;
                }

                // Server-side role verification
                const hasRole = await verifyRoleServer(requiredRole, token);
                setIsAuthorized(hasRole);
                
            } catch (error) {
                console.error('Role verification failed:', error);
                setError('Unable to verify role');
                setIsAuthorized(false);
            } finally {
                setIsLoading(false);
            }
        };

        checkRole();
    }, [requiredRole]);

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
                <div>Verifying role access...</div>
                <div style={{ fontSize: '0.9rem', color: '#6c757d', marginTop: '0.5rem' }}>
                    Checking {requiredRole} role
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

RequireRole.propTypes = {
    children: PropTypes.node.isRequired,
    requiredRole: PropTypes.string.isRequired,
    fallbackPath: PropTypes.string
};

RequireRole.defaultProps = {
    fallbackPath: '/unauthorized'
};

export default RequireRole;