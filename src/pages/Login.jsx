import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { setSession } from '../utils/SessionManager';

const Login = () => {
    const [identifier, setIdentifier] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);

        try {
            // Call new JWT login endpoint
            const response = await fetch('http://localhost:3001/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identifier, password })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            // Store JWT token and user data
            setSession({
                user: data.user,
                token: data.token,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
            });
            
            navigate('/dashboard');
            
        } catch (error) {
            console.error('Authentication failed:', error);
            setError(error.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="form-container">
            <h2>Welcome Back!</h2>
            {error && <p className="error">{error}</p>}
            <form onSubmit={handleSubmit}>
                <div className="input-box">
                    <input 
                        type="text" 
                        placeholder="Username or Email" 
                        value={identifier} 
                        onChange={(e) => setIdentifier(e.target.value)} 
                        disabled={isLoading}
                        required 
                    />
                </div>

                <div className="input-box">
                    <input 
                        type="password" 
                        placeholder="Password" 
                        value={password} 
                        onChange={(e) => setPassword(e.target.value)} 
                        disabled={isLoading}
                        required 
                    />
                </div>

                <button type="submit" disabled={isLoading}>
                    {isLoading ? 'Signing In...' : 'SIGN IN'}
                </button>
            </form>
            <p><Link to="/forgot-password">Forgot password?</Link></p>
            <p><Link to="/register">Don't have an account?</Link></p>
        </div>
    );
};

export default Login;
