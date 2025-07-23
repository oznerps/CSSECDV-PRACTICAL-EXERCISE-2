import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';

export default function Profile() {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [profileData, setProfileData] = useState({
        display_name: '',
        email: ''
    });
    const [message, setMessage] = useState('');
    const [isUpdating, setIsUpdating] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        const loadUserData = () => {
            try {
                // Check new session format first
                const sessionData = localStorage.getItem('auth_session');
                if (sessionData) {
                    const session = JSON.parse(sessionData);
                    if (session && session.user) {
                        setUser(session.user);
                        setProfileData({
                            display_name: session.user.display_name || '',
                            email: session.user.email || ''
                        });
                        setLoading(false);
                        return;
                    }
                }
                
                // Fallback to old session format
                const oldUserData = localStorage.getItem('currentUser');
                if (oldUserData) {
                    const parsedUser = JSON.parse(oldUserData);
                    setUser(parsedUser);
                    setProfileData({
                        display_name: parsedUser.display_name || '',
                        email: parsedUser.email || ''
                    });
                    setLoading(false);
                    return;
                }
                
                // No user found, redirect to login
                navigate('/login');
            } catch (error) {
                console.error('Error loading user data:', error);
                navigate('/login');
            }
        };

        loadUserData();
    }, [navigate]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMessage('');
        setIsUpdating(true);
        
        try {
            // Get current session
            const sessionData = localStorage.getItem('auth_session');
            if (!sessionData) {
                throw new Error('No session found');
            }

            const session = JSON.parse(sessionData);
            const token = session.token;

            // Call the server API to update user profile
            const response = await fetch(`http://localhost:3001/api/users/${user.id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                credentials: 'include',
                body: JSON.stringify({
                    display_name: profileData.display_name,
                    email: profileData.email
                })
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Failed to update profile');
            }

            // Update local session with new data
            session.user = {
                ...session.user,
                display_name: profileData.display_name,
                email: profileData.email,
                updated_at: new Date().toISOString()
            };
            
            localStorage.setItem('auth_session', JSON.stringify(session));
            setUser(session.user);
            setMessage('Profile updated successfully!');

        } catch (error) {
            console.error('Error updating profile:', error);
            setMessage(`Failed to update profile: ${error.message}`);
        } finally {
            setIsUpdating(false);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('auth_session');
        localStorage.removeItem('currentUser');
        navigate('/login');
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

    const formatDateTime = (dateString) => {
        if (!dateString) return 'Never';
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) return 'Never';
            return date.toLocaleString();
        } catch (error) {
            return 'Never';
        }
    };

    if (loading) {
        return (
            <div className="dashboard-container">
                <h2>Loading profile...</h2>
            </div>
        );
    }

    if (!user) {
        return (
            <div className="dashboard-container">
                <h2>Profile not found</h2>
                <p>Unable to load your profile. Please try logging in again.</p>
                <Link to="/login">Go to Login</Link>
            </div>
        );
    }

    return (
        <div className="dashboard-container">
            <h2>Your Profile</h2>
            
            {/* Current User Information */}
            <div style={{ 
                backgroundColor: '#f8f9fa', 
                padding: '1.5rem', 
                borderRadius: '8px',
                marginBottom: '2rem'
            }}>
                <h3>Current Information</h3>
                <p><strong>Username:</strong> {user.username}</p>
                <p><strong>Current Display Name:</strong> {user.display_name}</p>
                <p><strong>Current Email:</strong> {user.email}</p>
                <p><strong>Account Created:</strong> {formatDate(user.created_at)}</p>
                <p><strong>Last Login:</strong> {formatDateTime(user.last_login)}</p>
                {user.roles && user.roles.length > 0 && (
                    <p><strong>Roles:</strong> {
                        user.roles.map(role => 
                            typeof role === 'string' ? role : role.name
                        ).join(', ')
                    }</p>
                )}
            </div>

            {/* Update Form */}
            <div style={{ 
                backgroundColor: '#ffffff', 
                padding: '1.5rem', 
                borderRadius: '8px',
                border: '1px solid #dee2e6',
                marginBottom: '2rem'
            }}>
                <h3>Update Profile</h3>
                
                {message && (
                    <div style={{ 
                        padding: '1rem', 
                        marginBottom: '1rem',
                        backgroundColor: message.includes('successfully') ? '#d4edda' : '#f8d7da',
                        color: message.includes('successfully') ? '#155724' : '#721c24',
                        border: `1px solid ${message.includes('successfully') ? '#c3e6cb' : '#f5c6cb'}`,
                        borderRadius: '4px'
                    }}>
                        {message}
                    </div>
                )}
                
                <form onSubmit={handleSubmit}>
                    <div style={{ marginBottom: '1rem' }}>
                        <label style={{ 
                            display: 'block', 
                            marginBottom: '0.5rem', 
                            fontWeight: 'bold' 
                        }}>
                            Display Name:
                        </label>
                        <input
                            type="text"
                            value={profileData.display_name}
                            onChange={(e) => setProfileData({
                                ...profileData, 
                                display_name: e.target.value
                            })}
                            style={{
                                width: '100%',
                                padding: '0.75rem',
                                border: '1px solid #ced4da',
                                borderRadius: '4px',
                                fontSize: '1rem',
                                maxWidth: '400px'
                            }}
                            required
                            disabled={isUpdating}
                        />
                    </div>
                    
                    <div style={{ marginBottom: '1.5rem' }}>
                        <label style={{ 
                            display: 'block', 
                            marginBottom: '0.5rem', 
                            fontWeight: 'bold' 
                        }}>
                            Email Address:
                        </label>
                        <input
                            type="email"
                            value={profileData.email}
                            onChange={(e) => setProfileData({
                                ...profileData, 
                                email: e.target.value
                            })}
                            style={{
                                width: '100%',
                                padding: '0.75rem',
                                border: '1px solid #ced4da',
                                borderRadius: '4px',
                                fontSize: '1rem',
                                maxWidth: '400px'
                            }}
                            required
                            disabled={isUpdating}
                        />
                    </div>
                    
                    <button 
                        type="submit"
                        disabled={isUpdating}
                        style={{
                            padding: '0.75rem 1.5rem',
                            backgroundColor: isUpdating ? '#6c757d' : '#007bff',
                            color: 'white',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: isUpdating ? 'not-allowed' : 'pointer',
                            fontWeight: 'bold',
                            marginRight: '1rem'
                        }}
                    >
                        {isUpdating ? 'Updating...' : 'Save Changes'}
                    </button>
                    
                    <Link 
                        to="/dashboard"
                        style={{
                            padding: '0.75rem 1.5rem',
                            backgroundColor: '#6c757d',
                            color: 'white',
                            textDecoration: 'none',
                            borderRadius: '4px',
                            fontWeight: 'bold'
                        }}
                    >
                        Back to Dashboard
                    </Link>
                </form>
            </div>

            {/* Navigation Options */}
            <div style={{ 
                backgroundColor: '#e9ecef', 
                padding: '1rem', 
                borderRadius: '4px',
                marginBottom: '2rem'
            }}>
                <h4>Quick Navigation</h4>
                <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                    <Link to="/dashboard" style={{ color: '#007bff', textDecoration: 'none' }}>
                        Dashboard
                    </Link>
                    {user.roles && user.roles.some(role => 
                        (typeof role === 'string' ? role : role.name) === 'admin'
                    ) && (
                        <>
                            <Link to="/admin" style={{ color: '#dc3545', textDecoration: 'none' }}>
                                Admin Dashboard
                            </Link>
                            <Link to="/users" style={{ color: '#28a745', textDecoration: 'none' }}>
                                User Management
                            </Link>
                        </>
                    )}
                </div>
            </div>

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
        </div>
    );
}