import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useState, useEffect } from 'react';

const NavBar = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    const checkUserSession = () => {
        try {
            // Check new session format first
            const sessionData = localStorage.getItem('auth_session');
            if (sessionData) {
                const session = JSON.parse(sessionData);
                if (session && session.user) {
                    setUser(session.user);
                    setLoading(false);
                    return;
                }
            }
            
            // Fallback to old session format
            const oldUserData = localStorage.getItem('currentUser');
            if (oldUserData) {
                const parsedUser = JSON.parse(oldUserData);
                setUser(parsedUser);
                setLoading(false);
                return;
            }
            
            // No user found
            setUser(null);
            setLoading(false);
        } catch (error) {
            console.error('Error checking user session:', error);
            setUser(null);
            setLoading(false);
        }
    };

    useEffect(() => {
        // Check on component mount
        checkUserSession();

        // Listen for storage changes (when user logs in/out in another tab)
        const handleStorageChange = (e) => {
            if (e.key === 'auth_session' || e.key === 'currentUser') {
                checkUserSession();
            }
        };

        window.addEventListener('storage', handleStorageChange);
        
        // Also check on route changes (in case session was updated)
        checkUserSession();
        
        // Cleanup
        return () => {
            window.removeEventListener('storage', handleStorageChange);
        };
    }, [location.pathname]); // Re-check when route changes

    const handleLogout = async () => {
        try {
            // Get current session for the token
            const sessionData = localStorage.getItem('auth_session');
            let token = null;
            
            if (sessionData) {
                const session = JSON.parse(sessionData);
                token = session.token;
            }
            
            // Call server logout endpoint if we have a token
            if (token) {
                await fetch('http://localhost:3001/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include'
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
            // Continue with client-side cleanup even if server logout fails
        } finally {
            // Clear user session (always do this)
            localStorage.removeItem('auth_session');
            localStorage.removeItem('currentUser');
            setUser(null);
            // Redirect to login page
            navigate('/login');
        }
    };

    const hasRole = (roleName) => {
        if (!user || !user.roles) return false;
        return user.roles.some(role => 
            typeof role === 'string' ? role === roleName : role.name === roleName
        );
    };

    if (loading) {
        return (
            <nav className="navbar">
                <div className="container">
                    <Link to="/" style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>
                        CSSECDV-PRACTICAL-EXERCISE-3
                    </Link>
                    <div>Loading...</div>
                </div>
            </nav>
        );
    }

    return (
        <nav className="navbar">
            <div className="container">
                <Link to="/" style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>
                    CSSECDV-PRACTICAL-EXERCISE-3
                </Link>
                
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    {user ? (
                        // Authenticated user navigation - SIMPLIFIED
                        <>
                            <span style={{ 
                                marginRight: '1rem', 
                                fontWeight: 'bold',
                                color: hasRole('admin') ? '#dc3545' : '#28a745'
                            }}>
                                Welcome, {user.display_name || user.username}
                                {hasRole('admin') && <span style={{ fontSize: '0.8rem', marginLeft: '0.5rem' }}>(Admin)</span>}
                            </span>
                            
                            {/* Basic navigation only */}
                            <Link to="/dashboard">Dashboard</Link>
                            <Link to="/profile">Profile</Link>
                            
                            <button 
                                onClick={handleLogout}
                                style={{
                                    backgroundColor: '#dc3545',
                                    color: 'white',
                                    border: 'none',
                                    padding: '0.5rem 1rem',
                                    borderRadius: '4px',
                                    cursor: 'pointer'
                                }}
                            >
                                Logout
                            </button>
                        </>
                    ) : (
                        // Non-authenticated user navigation
                        <>
                            <Link to="/login">Login</Link>
                            <Link to="/register">Register</Link>
                        </>
                    )}
                </div>
            </div>
        </nav>
    );
};

export default NavBar;