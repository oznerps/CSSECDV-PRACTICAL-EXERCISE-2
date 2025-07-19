import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import UserTemplate from "../components/UserTemplate.jsx";
import { getAllUsersWithRoles, getAllRoles, updateUserRoles } from '../utils/databaseAPI.js';

const AdminDashboard = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [users, setUsers] = useState([]);
    const [roles, setRoles] = useState([]);
    const [systemStats, setSystemStats] = useState({
        totalUsers: 0,
        totalRoles: 3,
        totalPermissions: 5
    });
    const [activeSection, setActiveSection] = useState('overview');
    const [fetchError, setFetchError] = useState(null);
    const [profileData, setProfileData] = useState({
        display_name: '',
        email: ''
    });
    const [profileMessage, setProfileMessage] = useState('');
    const navigate = useNavigate();

    useEffect(() => {
        const loadUserData = () => {
            try {
                const userData = localStorage.getItem('auth_session');
                if (userData) {
                    const session = JSON.parse(userData);
                    if (session && session.user) {
                        setUser(session.user);
                        setProfileData({
                            display_name: session.user.display_name || '',
                            email: session.user.email || ''
                        });
                    } else {
                        navigate('/login');
                    }
                } else {
                    const oldUserData = localStorage.getItem('currentUser');
                    if (oldUserData) {
                        const parsedUser = JSON.parse(oldUserData);
                        setUser(parsedUser);
                        setProfileData({
                            display_name: parsedUser.display_name || '',
                            email: parsedUser.email || ''
                        });
                    } else {
                        navigate('/login');
                    }
                }
            } catch (error) {
                console.error('Error loading user data:', error);
                navigate('/login');
            } finally {
                setLoading(false);
            }
        };

        loadUserData();
    }, [navigate]);

    // Load users and roles when switching to user management section
    useEffect(() => {
        if (activeSection === 'users' && user) {
            loadUsersAndRoles();
        }
    }, [activeSection, user]);

    const loadUsersAndRoles = async () => {
        try {
            setFetchError(null);
            const [usersData, rolesData] = await Promise.all([
                getAllUsersWithRoles(),
                getAllRoles()
            ]);
            
            setUsers(usersData);
            setRoles(rolesData);
            setSystemStats(prev => ({
                ...prev,
                totalUsers: usersData.length,
                totalRoles: rolesData.length
            }));
        } catch (error) {
            console.error('Error loading users and roles:', error);
            setFetchError('Failed to load users and roles');
        }
    };

    const refreshUserList = async () => {
        await loadUsersAndRoles();
    };

    const handleLogout = () => {
        localStorage.removeItem('auth_session');
        localStorage.removeItem('currentUser');
        navigate('/login');
    };

    const handleProfileUpdate = async (e) => {
        e.preventDefault();
        setProfileMessage('');
        
        try {
            // Here you would typically call an API to update the profile
            // For now, we'll just update the local storage
            const sessionData = localStorage.getItem('auth_session');
            if (sessionData) {
                const session = JSON.parse(sessionData);
                session.user = {
                    ...session.user,
                    display_name: profileData.display_name,
                    email: profileData.email
                };
                localStorage.setItem('auth_session', JSON.stringify(session));
                setUser(session.user);
                setProfileMessage('Profile updated successfully!');
            }
        } catch (error) {
            console.error('Error updating profile:', error);
            setProfileMessage('Failed to update profile. Please try again.');
        }
    };

    const formatDate = (dateString) => {
        if (!dateString) return 'Not available';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Not available';
            return date.toLocaleDateString();
        } catch (error) {
            return 'Not available';
        }
    };

    if (loading) {
        return (
            <div className="dashboard-container">
                <p>Loading admin dashboard...</p>
            </div>
        );
    }

    const renderOverview = () => (
        <>
            <p style={{ 
                backgroundColor: '#d4edda', 
                color: '#155724', 
                padding: '1rem', 
                borderRadius: '4px',
                marginBottom: '2rem'
            }}>
                Welcome to the Admin Dashboard! You have successfully accessed the admin area.
            </p>
            
            {/* Admin User Info */}
            <div className="user-info" style={{ marginBottom: '2rem' }}>
                <h3>Admin User Information</h3>
                <p><strong>Username:</strong> {user.username}</p>
                <p><strong>Display Name:</strong> {user.display_name}</p>
                <p><strong>Email:</strong> {user.email}</p>
                <p><strong>Account Created:</strong> {formatDate(user.created_at)}</p>
                <p><strong>Current Roles:</strong> {
                    user.roles ? user.roles.map(role => 
                        typeof role === 'string' ? role : role.name
                    ).join(', ') : 'Loading...'
                }</p>
            </div>

            {/* System Statistics */}
            <div style={{ 
                backgroundColor: '#f8f9fa', 
                padding: '1.5rem', 
                borderRadius: '8px',
                marginBottom: '2rem'
            }}>
                <h3>System Statistics</h3>
                <div style={{ 
                    display: 'grid', 
                    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                    gap: '1rem' 
                }}>
                    <div style={{ 
                        backgroundColor: '#007bff', 
                        color: 'white', 
                        padding: '1rem', 
                        borderRadius: '4px',
                        textAlign: 'center'
                    }}>
                        <h4>Users</h4>
                        <p style={{ fontSize: '2rem', margin: '0' }}>{systemStats.totalUsers}</p>
                    </div>
                    <div style={{ 
                        backgroundColor: '#28a745', 
                        color: 'white', 
                        padding: '1rem', 
                        borderRadius: '4px',
                        textAlign: 'center'
                    }}>
                        <h4>Roles</h4>
                        <p style={{ fontSize: '2rem', margin: '0' }}>{systemStats.totalRoles}</p>
                    </div>
                    <div style={{ 
                        backgroundColor: '#ffc107', 
                        color: 'black', 
                        padding: '1rem', 
                        borderRadius: '4px',
                        textAlign: 'center'
                    }}>
                        <h4>Permissions</h4>
                        <p style={{ fontSize: '2rem', margin: '0' }}>{systemStats.totalPermissions}</p>
                    </div>
                </div>
            </div>
        </>
    );

    const renderUserManagement = () => (
        <div>
            <h3>User Management & Role Assignment</h3>
            {fetchError && <p style={{color: 'red'}}>{fetchError}</p>}
            
            {users.length > 0 && (
                <div className="users">
                    <div className="userlist">
                        {/* Header row for the user list */}
                        <div className="user-entry user-header">
                            <h3>Username</h3>
                            <h3>Display Name</h3>
                            <h3>Email</h3>
                            <h3>Last Login</h3>
                            <h3>Roles & Management</h3>
                        </div>
                        
                        {/* User rows with role management capability */}
                        {users.map(userItem => (
                            <UserTemplate 
                                key={userItem.id} 
                                user={userItem}
                                onUserUpdate={refreshUserList}
                            />
                        ))}
                    </div>
                </div>
            )}
            
            {users.length === 0 && !fetchError && (
                <p>No users found in the system.</p>
            )}
        </div>
    );

    const renderProfileManagement = () => (
        <div>
            <h3>Profile Management</h3>
            {profileMessage && (
                <div style={{ 
                    padding: '1rem', 
                    marginBottom: '1rem',
                    backgroundColor: profileMessage.includes('success') ? '#d4edda' : '#f8d7da',
                    color: profileMessage.includes('success') ? '#155724' : '#721c24',
                    borderRadius: '4px'
                }}>
                    {profileMessage}
                </div>
            )}
            
            <form onSubmit={handleProfileUpdate} style={{ maxWidth: '400px' }}>
                <div style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>
                        Display Name:
                    </label>
                    <input
                        type="text"
                        value={profileData.display_name}
                        onChange={(e) => setProfileData({...profileData, display_name: e.target.value})}
                        style={{
                            width: '100%',
                            padding: '0.5rem',
                            border: '1px solid #ccc',
                            borderRadius: '4px',
                            fontSize: '1rem'
                        }}
                        required
                    />
                </div>
                
                <div style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>
                        Email:
                    </label>
                    <input
                        type="email"
                        value={profileData.email}
                        onChange={(e) => setProfileData({...profileData, email: e.target.value})}
                        style={{
                            width: '100%',
                            padding: '0.5rem',
                            border: '1px solid #ccc',
                            borderRadius: '4px',
                            fontSize: '1rem'
                        }}
                        required
                    />
                </div>
                
                <button 
                    type="submit"
                    style={{
                        padding: '0.75rem 1.5rem',
                        backgroundColor: '#007bff',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontWeight: 'bold'
                    }}
                >
                    Update Profile
                </button>
            </form>
        </div>
    );

    const renderSecurityInfo = () => (
        <div style={{ 
            backgroundColor: '#fff3cd', 
            border: '1px solid #ffeaa7',
            padding: '1rem', 
            borderRadius: '4px',
            marginBottom: '2rem'
        }}>
            <h4>Security Notice</h4>
            <p>You are logged in as an administrator. Please ensure you:</p>
            <ul>
                <li>Log out when finished with admin tasks</li>
                <li>Do not share your admin credentials</li>
                <li>Review user permissions regularly</li>
                <li>Monitor system access logs</li>
            </ul>
        </div>
    );

    return (
        <div className="dashboard-container">
            <h1>Admin Dashboard</h1>
            
            {user ? (
                <>
                    {/* Navigation Tabs */}
                    <div style={{ 
                        marginBottom: '2rem',
                        borderBottom: '1px solid #dee2e6'
                    }}>
                        <div style={{ display: 'flex', gap: '0' }}>
                            <button
                                onClick={() => setActiveSection('overview')}
                                style={{
                                    padding: '1rem 2rem',
                                    border: 'none',
                                    backgroundColor: activeSection === 'overview' ? '#007bff' : '#f8f9fa',
                                    color: activeSection === 'overview' ? 'white' : '#6c757d',
                                    cursor: 'pointer',
                                    borderTopLeftRadius: '4px',
                                    borderTopRightRadius: '4px',
                                    fontWeight: activeSection === 'overview' ? 'bold' : 'normal'
                                }}
                            >
                                Overview
                            </button>
                            <button
                                onClick={() => setActiveSection('users')}
                                style={{
                                    padding: '1rem 2rem',
                                    border: 'none',
                                    backgroundColor: activeSection === 'users' ? '#007bff' : '#f8f9fa',
                                    color: activeSection === 'users' ? 'white' : '#6c757d',
                                    cursor: 'pointer',
                                    borderTopLeftRadius: '4px',
                                    borderTopRightRadius: '4px',
                                    fontWeight: activeSection === 'users' ? 'bold' : 'normal'
                                }}
                            >
                                User Management
                            </button>
                            <button
                                onClick={() => setActiveSection('profile')}
                                style={{
                                    padding: '1rem 2rem',
                                    border: 'none',
                                    backgroundColor: activeSection === 'profile' ? '#007bff' : '#f8f9fa',
                                    color: activeSection === 'profile' ? 'white' : '#6c757d',
                                    cursor: 'pointer',
                                    borderTopLeftRadius: '4px',
                                    borderTopRightRadius: '4px',
                                    fontWeight: activeSection === 'profile' ? 'bold' : 'normal'
                                }}
                            >
                                Profile Settings
                            </button>
                        </div>
                    </div>

                    {/* Content based on active section */}
                    {activeSection === 'overview' && renderOverview()}
                    {activeSection === 'users' && renderUserManagement()}
                    {activeSection === 'profile' && renderProfileManagement()}

                    {/* Security Information - always visible */}
                    {renderSecurityInfo()}

                    <button onClick={handleLogout} style={{
                        padding: '0.75rem 1.5rem',
                        backgroundColor: '#dc3545',
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
                <p>Admin user data not available</p>
            )}
        </div>
    );
};

export default AdminDashboard;