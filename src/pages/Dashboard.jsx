import { useState, useEffect } from 'react';
import { supabase } from '../supabaseClient';

const Dashboard = () => {
    const [user, setUser] = useState(null);

    useEffect(() => {
        const session = supabase.auth.session();
        setUser(session?.user ?? null);
        const { data: listener } = supabase.auth.onAuthStateChange((_e, session) => setUser(session?.user ?? null));
        return () => listener.unsubscribe();
    }, []);

    return (
        <div className="dashboard-container">
            <h2>Dashboard</h2>
            {user ? (
                <div className="user-info">
                    <p><strong>Username:</strong> {user.user_metadata.username}</p>
                    <p><strong>Email:</strong> {user.email}</p>
                    <button onClick={() => supabase.auth.api.resetPasswordForEmail(user.email)}>Forgot Password</button>
                </div>
            ) : (
                <p>Loading...</p>
            )}
        </div>
    );
};

export default Dashboard;