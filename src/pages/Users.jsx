import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import UserTemplate from "../components/UserTemplate.jsx";
import { getAllUsersWithRoles } from '../utils/databaseAPI.js';

const UserManagement = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [fetchError, setFetchError] = useState(null);
    const [users, setUsers] = useState(null);
    const navigate = useNavigate();

    // Session management
    useEffect(() => {
        const loadUserData = () => {
            try {
                const userData = localStorage.getItem('currentUser');
                if (userData) {
                    const parsedUser = JSON.parse(userData);
                    setUser(parsedUser);
                } else {
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

    // Function to refresh user list after role changes
    const refreshUserList = async () => {
        try {
            setFetchError(null);
            // RBAC function that includes role information
            const usersData = await getAllUsersWithRoles();
            setUsers(usersData);
            console.log('Users with roles loaded:', usersData);
        } catch (error) {
            setFetchError('Could not refresh user list');
            setUsers(null);
            console.error('Error refreshing users:', error);
        }
    };

    // Fetch users with roles on component mount
    useEffect(() => {
        const fetchUsersWithRoles = async () => {
            try {
                setFetchError(null);
                // This function returns users with their complete role information
                const usersData = await getAllUsersWithRoles();
                setUsers(usersData);
                console.log('Initial users with roles loaded:', usersData);
            } catch (error) {
                setFetchError('Could not fetch users with roles');
                setUsers(null);
                console.error('Error fetching users with roles:', error);
            }
        };
        
        // Only fetch after user authentication is confirmed
        if (user) {
            fetchUsersWithRoles();
        }
    }, [user]); // Depend on user being loaded

    const handleLogout = () => {
        localStorage.removeItem('currentUser');
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
            
            {fetchError && <p style={{color: 'red'}}>{fetchError}</p>}
            
            {users && (
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
                                // Pass the refresh function so roles update immediately
                                onUserUpdate={refreshUserList}
                            />
                        ))}
                    </div>
                </div>
            )}
            
            {users && users.length === 0 && (
                <p>No users found in the system.</p>
            )}
        </div>
    );
};

export default UserManagement;