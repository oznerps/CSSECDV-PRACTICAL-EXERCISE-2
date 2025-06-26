import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { registerUser } from '../utils/databaseAPI';

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        displayName: '',
        email: '',
        password: ''
    });
    const [errors, setErrors] = useState({});
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleInputChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
        
        // Clear error for this field when user starts typing
        if (errors[name]) {
            setErrors(prev => ({
                ...prev,
                [name]: ''
            }));
        }
    };

    const validateForm = () => {
        const newErrors = {};
        
        // Basic client-side validation
        if (!formData.username.trim()) {
            newErrors.username = 'Username is required';
        }
        
        if (!formData.displayName.trim()) {
            newErrors.displayName = 'Display name is required';
        }
        
        if (!formData.email.trim()) {
            newErrors.email = 'Email is required';
        }
        
        if (!formData.password) {
            newErrors.password = 'Password is required';
        }
        
        setErrors(newErrors);
        return Object.keys(newErrors).length === 0;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        
        if (!validateForm()) {
            return;
        }
        
        setIsLoading(true);
        setErrors({});
        
        try {
            await registerUser(formData);
            
            // Registration successful
            alert('Registration successful! You can now log in.');
            navigate('/login');
            
        } catch (error) {
            // Display specific error message
            setErrors({ submit: error.message });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="form-container">
            <h2>Create Your Account</h2>
            
            {errors.submit && (
                <div className="error" style={{ marginBottom: '1rem' }}>
                    {errors.submit}
                </div>
            )}
            
            <form onSubmit={handleSubmit}>
                <div className="input-group">
                    <input
                        type="text"
                        name="username"
                        placeholder="Username (3-30 characters)"
                        value={formData.username}
                        onChange={handleInputChange}
                        disabled={isLoading}
                        required
                    />
                    {errors.username && (
                        <div className="error">{errors.username}</div>
                    )}
                </div>

                <div className="input-group">
                    <input
                        type="text"
                        name="displayName"
                        placeholder="Display Name"
                        value={formData.displayName}
                        onChange={handleInputChange}
                        disabled={isLoading}
                        required
                    />
                    {errors.displayName && (
                        <div className="error">{errors.displayName}</div>
                    )}
                </div>

                <div className="input-group">
                    <input
                        type="email"
                        name="email"
                        placeholder="Email Address"
                        value={formData.email}
                        onChange={handleInputChange}
                        disabled={isLoading}
                        required
                    />
                    {errors.email && (
                        <div className="error">{errors.email}</div>
                    )}
                </div>

                <div className="input-group">
                    <input
                        type="password"
                        name="password"
                        placeholder="Password (8+ characters)"
                        value={formData.password}
                        onChange={handleInputChange}
                        disabled={isLoading}
                        required
                    />
                    {errors.password && (
                        <div className="error">{errors.password}</div>
                    )}
                </div>

                <button type="submit" disabled={isLoading}>
                    {isLoading ? 'Creating Account...' : 'Create Account'}
                </button>
            </form>
            
            <p>
                Already have an account? <Link to="/login">Sign in here</Link>
            </p>
        </div>
    );
};

export default Register;