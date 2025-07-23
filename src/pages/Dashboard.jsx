import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { useSessionTimeout } from '../contexts/SessionTimeoutContext';
import DashboardCard from '../components/DashboardCard';
import UserInfoCard from '../components/UserInfoCard';
import LoadingSpinner from '../components/LoadingSpinner';

const Dashboard = () => {
    const navigate = useNavigate();
    const { resetSessionTimers } = useSessionTimeout();
    const { 
        user, 
        loading, 
        error, 
        hasRole, 
        hasPermission, 
        getRoleLevel 
    } = useAuth();

    const handleCardClick = (path) => {
        resetSessionTimers(); // Reset session on user activity
        navigate(path);
    };

    if (loading) {
        return <LoadingSpinner size="large" message="Loading your dashboard..." />;
    }

    if (error || !user) {
        return (
            <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '50vh',
                flexDirection: 'column',
                color: '#dc3545'
            }}>
                <h3>Error Loading Dashboard</h3>
                <p>{error || 'User data not available'}</p>
                <button 
                    onClick={() => navigate('/login')}
                    style={{
                        padding: '0.75rem 1.5rem',
                        backgroundColor: '#007bff',
                        color: 'white',
                        border: 'none',
                        borderRadius: '6px',
                        cursor: 'pointer'
                    }}
                >
                    Return to Login
                </button>
            </div>
        );
    }

    const getAvailableActions = () => {
        const actions = [];
        
        // Home - Available to all users
        actions.push({
            id: 'home',
            title: 'Home',
            description: 'Return to the welcome home page',
            icon: '🏠',
            linkTo: '/home',
            backgroundColor: '#6f42c1'
        });

        // Profile - Available to all users
        actions.push({
            id: 'profile',
            title: 'Edit Profile',
            description: 'Update your personal information and settings',
            icon: '👤',
            linkTo: '/profile',
            backgroundColor: '#007bff'
        });

        // User Management - Managers and Admins
        if (hasRole('manager') || hasPermission('manage_users')) {
            actions.push({
                id: 'users',
                title: 'User Management',
                description: 'Manage users, roles, and permissions',
                icon: '👥',
                linkTo: '/users',
                backgroundColor: '#28a745'
            });
        }

        // Admin Dashboard - Admins only
        if (hasRole('admin')) {
            actions.push({
                id: 'admin',
                title: 'Admin Dashboard',
                description: 'Full system administration and controls',
                icon: '🛡️',
                linkTo: '/admin',
                backgroundColor: '#dc3545'
            });
        }

        return actions;
    };

    const getRoleMessage = () => {
        const roleLevel = getRoleLevel();
        switch (roleLevel) {
            case 'admin':
                return {
                    title: 'Administrator Access',
                    message: 'You have full system privileges and access to all features.',
                    color: '#dc3545'
                };
            case 'manager':
                return {
                    title: 'Manager Access',
                    message: 'You can manage users and have elevated permissions.',
                    color: '#28a745'
                };
            default:
                return {
                    title: 'Standard Access',
                    message: 'Welcome! You have access to your profile and basic features.',
                    color: '#007bff'
                };
        }
    };

    const roleMessage = getRoleMessage();
    const availableActions = getAvailableActions();

    return (
        <div style={{
            minHeight: '100vh',
            backgroundColor: '#f8f9fa',
            padding: '2rem 1rem'
        }}>
            <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
                {/* Role-based welcome banner */}
                <div style={{
                    backgroundColor: roleMessage.color,
                    color: 'white',
                    padding: '2rem',
                    borderRadius: '12px',
                    marginBottom: '2rem',
                    textAlign: 'center',
                    boxShadow: '0 4px 16px rgba(0,0,0,0.1)'
                }}>
                    <h1 style={{ margin: '0 0 0.5rem 0', fontSize: '2rem' }}>
                        {roleMessage.title}
                    </h1>
                    <p style={{ margin: 0, fontSize: '1.1rem', opacity: 0.9 }}>
                        {roleMessage.message}
                    </p>
                </div>

                {/* User Information Card */}
                <UserInfoCard user={user} />

                {/* Available Actions */}
                <div style={{
                    backgroundColor: 'white',
                    padding: '2rem',
                    borderRadius: '12px',
                    boxShadow: '0 2px 12px rgba(0,0,0,0.1)'
                }}>
                    <h2 style={{ 
                        margin: '0 0 1.5rem 0', 
                        color: '#333',
                        fontSize: '1.5rem'
                    }}>
                        Available Actions
                    </h2>
                    
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                        gap: '1.5rem'
                    }}>
                        {availableActions.map(action => (
                            <DashboardCard
                                key={action.id}
                                title={action.title}
                                description={action.description}
                                icon={action.icon}
                                linkTo={action.linkTo}
                                backgroundColor={action.backgroundColor}
                            />
                        ))}
                    </div>

                    {/* Role-specific information */}
                    <div style={{
                        marginTop: '2rem',
                        padding: '1rem',
                        backgroundColor: '#f8f9fa',
                        borderRadius: '8px',
                        borderLeft: `4px solid ${roleMessage.color}`
                    }}>
                        <p style={{ 
                            margin: 0, 
                            fontSize: '0.9rem',
                            color: '#666'
                        }}>
                            <strong>Access Level:</strong> {getRoleLevel().toUpperCase()} • 
                            <strong> Available Features:</strong> {availableActions.length} • 
                            <strong> Session:</strong> Secure & Active
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;