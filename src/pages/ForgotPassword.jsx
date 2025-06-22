import { useState } from 'react';
import { supabase } from '../supabaseClient';
import { Link } from 'react-router-dom';

const ForgotPassword = () => {
    const [email, setEmail] = useState('');
    const [message, setMessage] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        const { error } = await supabase.auth.api.resetPasswordForEmail(email);
        if (error) setMessage(error.message);
        else setMessage('If that email is registered, a reset link has been sent.');
    };

    return (
        <div className="form-container">
            <h2>Reset Password</h2>
            {message && <p>{message}</p>}
            <form onSubmit={handleSubmit}>
                <input type="email" placeholder="Your registered email" value={email} onChange={(e) => setEmail(e.target.value)} required />
                <button type="submit">Send Reset Email</button>
            </form>
            <p><Link to="/login">Back to login</Link></p>
        </div>
    );
};

export default ForgotPassword;