import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { authenticateUser } from '../utils/databaseAPI';
import { setSession } from '../utils/sessionmanager';

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
            // our auth system not supasupa
            const user = await authenticateUser(identifier, password);

            // Choose the first role (or prioritize if needed)
            const primaryRole = user.roles.length > 0 ? user.roles[0] : 'user';

            // Store session with a flat 'role' for ProtectedRoute
            setSession({ ...user, role: primaryRole });
            
            // Success - redirect to dashboard
            navigate('/Dashboard');
            
        } catch (error) {
            console.error('Authentication failed:', error);
            // Show the error from your validation system
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