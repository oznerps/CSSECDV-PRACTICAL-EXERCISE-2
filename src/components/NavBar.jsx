import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useSessionTimeout } from '../contexts/SessionTimeoutContext';
import { useAuth } from '../hooks/useAuth';
import { authAPI } from '../utils/apiInterceptor';
import { clearSessionCookie } from '../utils/cookieUtils';

const NavBar = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { resetSessionTimers } = useSessionTimeout();
    const { user, loading, hasRole } = useAuth();

    // Handle user activity to reset session timers
    const handleUserActivity = () => {
        if (user) {
            resetSessionTimers();
        }
    };

    const handleLogout = async () => {
        try {
            // Use the API interceptor for logout
            await authAPI.logout();
        } catch (error) {
            console.error('Logout error:', error);
            // Continue with client-side cleanup even if server logout fails
        } finally {
            // Clear user session and cookies (always do this)
            localStorage.removeItem('auth_session');
            localStorage.removeItem('currentUser');
            clearSessionCookie();
            // Redirect to login page
            navigate('/login');
        }
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
                <Link 
                    to={user ? "/home" : "/"} 
                    onClick={handleUserActivity}
                    style={{ fontWeight: 'bold', fontSize: '1.1rem' }}
                >
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
                            
                            {/* Basic navigation */}
                            <Link to="/home" onClick={handleUserActivity}>Home</Link>
                            <Link to="/dashboard" onClick={handleUserActivity}>Dashboard</Link>
                            <Link to="/profile" onClick={handleUserActivity}>Profile</Link>
                            
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