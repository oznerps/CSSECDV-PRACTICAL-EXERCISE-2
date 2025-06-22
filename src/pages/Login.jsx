import { useState } from 'react';
import { supabase } from '../supabaseClient';
import { useNavigate, Link } from 'react-router-dom';

const Login = () => {
    const [identifier, setIdentifier] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        let emailToUse = identifier;
        if (!identifier.includes('@')) {
            const { data, error: lookupErr } = await supabase.from('users').select('email').eq('username', identifier.toLowerCase()).single();
            if (lookupErr || !data) {
                setError('Invalid username/email or password');
                return;
            }
            emailToUse = data.email;
        }
        const { error: signInError } = await supabase.auth.signIn({ email: emailToUse, password });
        if (signInError) setError('Invalid username/email or password');
        else navigate('/dashboard');
    };

    return (
        <div className="form-container">
            <h2>Login</h2>
            {error && <p className="error">{error}</p>}
            <form onSubmit={handleSubmit}>
                <input type="text" placeholder="Username or Email" value={identifier} onChange={(e) => setIdentifier(e.target.value)} required />
                <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                <button type="submit">Sign In</button>
            </form>
            <p><Link to="/forgot-password">Forgot password?</Link></p>
            <p><Link to="/register">Don't have an account?</Link></p>
        </div>
    );
};

export default Login;