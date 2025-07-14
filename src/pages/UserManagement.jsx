import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const UserManagement = () => {
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
            <div className="default-container">
                <p>Loading...</p>
            </div>
        );
    }

    return (
        <div className="default-container">
            <h1>User Management Page</h1>
            
        </div>
    );
};

export default UserManagement;