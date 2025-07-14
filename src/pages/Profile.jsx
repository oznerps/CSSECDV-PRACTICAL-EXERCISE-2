import { useState, useEffect } from 'react';
import { supabase } from '../supabaseClient';

export default function Profile() {
    const [user, setUser] = useState(null);
    const [displayName, setDisplayName] = useState('');
    const [message, setMessage] = useState('');

    useEffect(() => {
        const session = supabase.auth.session();
        if (session?.user) {
            setUser(session.user);
            setDisplayName(session.user.user_metadata?.display_name || '');
        }
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMessage('');
        // Update only the display_name metadata
        const { error } = await supabase.auth.updateUser({
            data: { display_name: displayName }
        });
        if (error) setMessage(error.message);
        else setMessage('Display name updated successfully.');
    };

    if (!user) return <p>Loading profile…</p>;

    return (
        <div className="dashboard-container">
            <h2>Your Profile</h2>
            {message && <p>{message}</p>}
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    value={displayName}
                    onChange={e => setDisplayName(e.target.value)}
                    placeholder="Display Name"
                    required
                />
                <button type="submit">Save Changes</button>
            </form>
        </div>
    );
}