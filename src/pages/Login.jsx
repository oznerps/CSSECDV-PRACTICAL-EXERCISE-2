import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { setSession, isAuthenticated } from '../utils/SessionManager';

const Login = () => {
    const [identifier, setIdentifier] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    // Redirect authenticated users to home
    useEffect(() => {
        if (isAuthenticated()) {
            console.log('User already authenticated, redirecting to home');
            navigate('/home', { replace: true });
        }
    }, [navigate]);

    const makeLoginRequest = async (retryCount = 0) => {
        const response = await fetch('http://localhost:3001/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // Required for session cookies
            body: JSON.stringify({ identifier, password })
        });

        // Clear stale data and retry on network errors
        if (!response.ok && retryCount === 0) {
            console.log('Login request failed, clearing stale data and retrying...');
            localStorage.clear();
            sessionStorage.clear();
            
            await new Promise(resolve => setTimeout(resolve, 1000));
            return makeLoginRequest(1);
        }

        return response;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setIsLoading(true);

        try {
            // Clear stale session data
            localStorage.removeItem('auth_session');
            localStorage.removeItem('currentUser');

            const response = await makeLoginRequest();
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Login failed');
            }

            // Store session data
            setSession({
                user: data.user,
                token: data.token,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
            });
            
            console.log('Login successful, redirecting to home page');
            
            // Force page refresh for auth state update
            window.location.href = '/home';
            
        } catch (error) {
            console.error('Authentication failed:', error);
            
            // Handle specific error types
            if (error.message.includes('Failed to fetch') || error.message.includes('CORS')) {
                setError('Connection error. Please check if the server is running and try again.');
            } else if (error.message.includes('expired')) {
                setError('Session expired. Please try logging in again.');
            } else {
                setError(error.message);
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleQuickFix = () => {
        console.log('Applying quick fix...');
        localStorage.clear();
        sessionStorage.clear();
        setError(null);
        window.location.reload();
    };

    return (
        <div className="form-container">
            <h2>Welcome Back!</h2>
            
            {error && (
                <div className="error" style={{ marginBottom: '1rem' }}>
                    <p>{error}</p>
                    {(error.includes('Connection error') || error.includes('CORS')) && (
                        <button 
                            onClick={handleQuickFix}
                            style={{
                                marginTop: '0.5rem',
                                padding: '0.5rem 1rem',
                                backgroundColor: '#ffc107',
                                color: '#000',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontSize: '0.9rem'
                            }}
                        >
                            🔧 Quick Fix - Clear Cache & Retry
                        </button>
                    )}
                </div>
            )}
            
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