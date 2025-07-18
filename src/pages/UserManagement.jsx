import { supabase } from "../supabaseClient";
import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

import UserTemplate from "../components/UserTemplate.jsx";


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
    
    //
    const[fetchError, setFetchError] = useState(null)
    const[users, setUsers] = useState(null)

    useEffect(() => {
        const fetchUsers = async () => {
            const { data, error} = await supabase
             .from('users')
             .select()


             if (error) {
                setFetchError('Could not fetch users')
                setUsers(null)
                console.log(error)
             }
             if (data) {
                setUsers(data)
                setFetchError(null)
             }
        }
        
        fetchUsers()
    },[])

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

            {fetchError&& (<p>{fetchError}</p>)}
            {users && (
                <div className="users">
                    <div className="userlist">
                        <div className="user-entry">
                            <h3>Username</h3>
                            <h3>Display Name</h3>
                            <h3>email</h3>
                            <h3>Last Login</h3>
                            <h3>Role</h3>
                            
                        </div>
                        {users.map(user => (
                        <UserTemplate key={user.id} user={user}/>
                    )
                    )}
                    </div>
                </div>
            )}
        </div>

        
    );
};

export default UserManagement;