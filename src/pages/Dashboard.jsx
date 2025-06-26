import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const Dashboard = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const loadUserData = () => {
            try {
                const userData = localStorage.getItem('currentUser');
                if (userData) {
                    const parsedUser = JSON.parse(userData);
                    setUser(parsedUser);
                } else {
                    // No user data found, redirect to login
                    navigate('/login');
                }
            } catch (error) {
                console.error('Error loading user data:', error);
                localStorage.removeItem('currentUser');
                navigate('/login');
            } finally {
                setLoading(false);
            }
        };

        loadUserData();
    }, [navigate]);

    const handleLogout = () => {
        // Clear user session
        localStorage.removeItem('currentUser');
        // Redirect to login
        navigate('/login');
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
                <div className="user-info">
                    <p><strong>Username:</strong> {user.display_name}</p>
                    <p><strong>Email:</strong> {user.email}</p>
                    <p><strong>Account Created:</strong> {new Date(user.created_at).toLocaleDateString()}</p>
                    {user.last_login && (
                        <p><strong>Last Login:</strong> {new Date(user.last_login).toLocaleString()}</p>
                    )}
                    <button onClick={handleLogout} style={{
                        marginTop: '1rem',
                        padding: '0.5rem 1rem',
                        backgroundColor: '#e67e22',
                        border: 'none',
                        borderRadius: '4px',
                        color: '#ffffff',
                        cursor: 'pointer'
                    }}>
                        Logout
                    </button>
                </div>
            ) : (
                <p>User data not available</p>
            )}
        </div>
    );
};

export default Dashboard;