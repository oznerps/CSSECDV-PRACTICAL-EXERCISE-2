import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';

const Dashboard = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const loadUserData = () => {
            try {
                const userData = localStorage.getItem('auth_session');
                if (userData) {
                    const session = JSON.parse(userData);
                    if (session && session.user) {
                        setUser(session.user);
                    } else {
                        navigate('/login');
                    }
                } else {
                    // Fallback to old session format
                    const oldUserData = localStorage.getItem('currentUser');
                    if (oldUserData) {
                        const parsedUser = JSON.parse(oldUserData);
                        setUser(parsedUser);
                    } else {
                        navigate('/login');
                    }
                }
            } catch (error) {
                console.error('Error loading user data:', error);
                localStorage.removeItem('auth_session');
                localStorage.removeItem('currentUser');
                navigate('/login');
            } finally {
                setLoading(false);
            }
        };

        loadUserData();
    }, [navigate]);

    const handleLogout = () => {
        // Clear all session data
        localStorage.removeItem('auth_session');
        localStorage.removeItem('currentUser');
        // Redirect to login
        navigate('/login');
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'Not available';
        
        try {
            const date = new Date(dateString);
            // Check if date is valid
            if (isNaN(date.getTime())) {
                return 'Not available';
            }
            return date.toLocaleDateString();
        } catch (error) {
            console.error('Error formatting date:', error);
            return 'Not available';
        }
    };

    const formatDateTime = (dateString) => {
        if (!dateString) return 'Never';
        
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return 'Never';
            }
            return date.toLocaleString();
        } catch (error) {
            console.error('Error formatting datetime:', error);
            return 'Never';
        }
    };

    const getUserRoles = () => {
        if (!user || !user.roles) return [];
        return Array.isArray(user.roles) ? user.roles : [];
    };

    const hasRole = (roleName) => {
        const roles = getUserRoles();
        return roles.some(role => 
            typeof role === 'string' ? role === roleName : role.name === roleName
        );
    };

    const hasPermission = (permissionName) => {
        if (!user || !user.permissions) return false;
        return user.permissions.includes(permissionName);
    };

    if (loading) {
        return (
            <div className="dashboard-container">
                <p>Loading...</p>
            </div>
        );
    }

    return (
        <div className="dashboard-container">
            <h2>Dashboard</h2>
            
            {user ? (
                <>
                    {/* Admin Access Banner - For Admin Users Only */}
                    {hasRole('admin') && (
                        <div style={{ 
                            backgroundColor: '#dc3545', 
                            color: 'white', 
                            padding: '1.5rem', 
                            borderRadius: '8px',
                            marginBottom: '2rem',
                            textAlign: 'center'
                        }}>
                            <h3 style={{ margin: '0 0 1rem 0' }}>🛡️ Administrator Access</h3>
                            <p style={{ margin: '0 0 1rem 0' }}>
                                You have full administrator privileges. Access all admin functions below.
                            </p>
                            <Link 
                                to="/admin" 
                                style={{ 
                                    padding: '1rem 2rem', 
                                    backgroundColor: 'white', 
                                    color: '#dc3545', 
                                    textDecoration: 'none', 
                                    borderRadius: '4px',
                                    fontWeight: 'bold',
                                    fontSize: '1.1rem',
                                    display: 'inline-block'
                                }}
                            >
                                Open Admin Dashboard
                            </Link>
                        </div>
                    )}

                    {/* Manager Access Banner - For Manager Users (Non-Admin) */}
                    {hasRole('manager') && !hasRole('admin') && (
                        <div style={{ 
                            backgroundColor: '#28a745', 
                            color: 'white', 
                            padding: '1.5rem', 
                            borderRadius: '8px',
                            marginBottom: '2rem',
                            textAlign: 'center'
                        }}>
                            <h3 style={{ margin: '0 0 1rem 0' }}>👥 Manager Access</h3>
                            <p style={{ margin: '0 0 1rem 0' }}>
                                You have manager privileges. Access user management functions below.
                            </p>
                            <Link 
                                to="/users" 
                                style={{ 
                                    padding: '1rem 2rem', 
                                    backgroundColor: 'white', 
                                    color: '#28a745', 
                                    textDecoration: 'none', 
                                    borderRadius: '4px',
                                    fontWeight: 'bold',
                                    fontSize: '1.1rem',
                                    display: 'inline-block'
                                }}
                            >
                                Open User Management
                            </Link>
                        </div>
                    )}

                    {/* User Information */}
                    <div className="user-info">
                        <p><strong>Username:</strong> {user.username || 'Not available'}</p>
                        <p><strong>Display Name:</strong> {user.display_name || 'Not available'}</p>
                        <p><strong>Email:</strong> {user.email || 'Not available'}</p>
                        <p><strong>Account Created:</strong> {formatDate(user.created_at)}</p>
                        <p><strong>Last Login:</strong> {formatDateTime(user.last_login)}</p>
                        
                        {/* Show user roles if available */}
                        {getUserRoles().length > 0 && (
                            <p><strong>Roles:</strong> {
                                getUserRoles().map(role => 
                                    typeof role === 'string' ? role : role.name
                                ).join(', ')
                            }</p>
                        )}
                    </div>

                    {/* Available Actions Based on Role */}
                    <div className="dashboard-navigation" style={{ 
                        marginTop: '2rem', 
                        padding: '1rem', 
                        backgroundColor: '#f8f9fa', 
                        borderRadius: '8px' 
                    }}>
                        <h3>Available Actions</h3>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                            
                            {/* Profile link - all authenticated users */}
                            <Link 
                                to="/profile" 
                                style={{ 
                                    padding: '0.75rem 1rem', 
                                    backgroundColor: '#007bff', 
                                    color: 'white', 
                                    textDecoration: 'none', 
                                    borderRadius: '4px',
                                    textAlign: 'center'
                                }}
                            >
                                📝 Edit Profile
                            </Link>

                            {/* User Management - for managers and admins */}
                            {(hasRole('manager') || hasPermission('manage_users')) && (
                                <Link 
                                    to="/users" 
                                    style={{ 
                                        padding: '0.75rem 1rem', 
                                        backgroundColor: '#28a745', 
                                        color: 'white', 
                                        textDecoration: 'none', 
                                        borderRadius: '4px',
                                        textAlign: 'center'
                                    }}
                                >
                                    👥 Manage Users & Roles
                                </Link>
                            )}

                            {/* Admin Dashboard - only for admin users */}
                            {hasRole('admin') && (
                                <Link 
                                    to="/admin" 
                                    style={{ 
                                        padding: '0.75rem 1rem', 
                                        backgroundColor: '#dc3545', 
                                        color: 'white', 
                                        textDecoration: 'none', 
                                        borderRadius: '4px',
                                        textAlign: 'center'
                                    }}
                                >
                                    🛡️ Admin Dashboard
                                </Link>
                            )}
                        </div>

                        {/* Role-specific notes */}
                        {hasRole('admin') && (
                            <div style={{
                                marginTop: '1rem',
                                padding: '0.75rem',
                                backgroundColor: '#fff3cd',
                                border: '1px solid #ffeaa7',
                                borderRadius: '4px',
                                fontSize: '0.9rem',
                                textAlign: 'center'
                            }}>
                                <strong>Admin Note:</strong> You have access to both user management and full admin dashboard with system controls.
                            </div>
                        )}

                        {hasRole('manager') && !hasRole('admin') && (
                            <div style={{
                                marginTop: '1rem',
                                padding: '0.75rem',
                                backgroundColor: '#d1ecf1',
                                border: '1px solid #bee5eb',
                                borderRadius: '4px',
                                fontSize: '0.9rem',
                                textAlign: 'center'
                            }}>
                                <strong>Manager Note:</strong> You can manage users and assign basic roles. Contact an admin for advanced system functions.
                            </div>
                        )}
                    </div>

                    <button onClick={handleLogout} style={{
                        marginTop: '2rem',
                        padding: '0.75rem 1.5rem',
                        backgroundColor: '#e67e22',
                        border: 'none',
                        borderRadius: '4px',
                        color: '#ffffff',
                        cursor: 'pointer',
                        fontWeight: 'bold'
                    }}>
                        Logout
                    </button>
                </>
            ) : (
                <p>User data not available</p>
            )}
        </div>
    );
};

export default Dashboard;