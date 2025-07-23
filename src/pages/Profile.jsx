import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { userAPI } from '../utils/apiInterceptor';
import LoadingSpinner from '../components/LoadingSpinner';
import { formatDate, formatUserFriendlyDateTime } from '../utils/dateUtils';

export default function Profile() {
    const { user, loading: authLoading, checkSession } = useAuth();
    const [profileData, setProfileData] = useState({
        display_name: '',
        email: ''
    });
    const [message, setMessage] = useState('');
    const [isUpdating, setIsUpdating] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        if (user) {
            setProfileData({
                display_name: user.display_name || '',
                email: user.email || ''
            });
        }
    }, [user]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setMessage('');
        setIsUpdating(true);
        
        try {
            const result = await userAPI.update(user.id, {
                display_name: profileData.display_name,
                email: profileData.email
            });

            // Refresh user data from server
            await checkSession();
            setMessage('Profile updated successfully!');

        } catch (error) {
            console.error('Error updating profile:', error);
            setMessage(`Failed to update profile: ${error.message}`);
        } finally {
            setIsUpdating(false);
        }
    };

    // Date formatting functions moved to dateUtils.js

    if (authLoading) {
        return <LoadingSpinner size="large" message="Loading your profile..." />;
    }

    if (!user) {
        return (
            <div style={{
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                height: '50vh',
                flexDirection: 'column',
                color: '#dc3545'
            }}>
                <h3>Profile not found</h3>
                <p>Unable to load your profile. You may need to log in again.</p>
            </div>
        );
    }

    return (
        <div style={{
            minHeight: '100vh',
            backgroundColor: '#f8f9fa',
            padding: '2rem 1rem'
        }}>
            <div style={{ maxWidth: '800px', margin: '0 auto' }}>
                <div style={{
                    backgroundColor: '#007bff',
                    color: 'white',
                    padding: '2rem',
                    borderRadius: '12px',
                    marginBottom: '2rem',
                    textAlign: 'center'
                }}>
                    <h1 style={{ margin: '0 0 0.5rem 0', fontSize: '2rem' }}>
                        Profile Settings
                    </h1>
                    <p style={{ margin: 0, fontSize: '1.1rem', opacity: 0.9 }}>
                        Manage your personal information and account settings
                    </p>
                </div>

                {/* Current User Information */}
                <div style={{ 
                    backgroundColor: 'white', 
                    padding: '2rem', 
                    borderRadius: '12px',
                    boxShadow: '0 2px 12px rgba(0,0,0,0.1)',
                    marginBottom: '2rem'
                }}>
                    <h3 style={{ margin: '0 0 1.5rem 0', color: '#333' }}>Current Information</h3>
                    
                    <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                        gap: '1rem',
                        marginBottom: '1rem'
                    }}>
                        <div>
                            <p style={{ margin: '0.5rem 0' }}>
                                <strong>Username:</strong> {user.username}
                            </p>
                            <p style={{ margin: '0.5rem 0' }}>
                                <strong>Display Name:</strong> {user.display_name || 'Not set'}
                            </p>
                            <p style={{ margin: '0.5rem 0' }}>
                                <strong>Email:</strong> {user.email}
                            </p>
                        </div>
                        <div>
                            <p style={{ margin: '0.5rem 0' }}>
                                <strong>Member Since:</strong> {formatDate(user.created_at)}
                            </p>
                            <p style={{ margin: '0.5rem 0' }}>
                                <strong>Last Login:</strong> {formatUserFriendlyDateTime(user.last_login)}
                            </p>
                            {user.roles && user.roles.length > 0 && (
                                <p style={{ margin: '0.5rem 0' }}>
                                    <strong>Roles:</strong> {
                                        user.roles.map(role => 
                                            typeof role === 'string' ? role : role.name
                                        ).join(', ')
                                    }
                                </p>
                            )}
                        </div>
                    </div>
                </div>

                {/* Update Form */}
                <div style={{ 
                    backgroundColor: 'white', 
                    padding: '2rem', 
                    borderRadius: '12px',
                    boxShadow: '0 2px 12px rgba(0,0,0,0.1)'
                }}>
                    <h3 style={{ margin: '0 0 1.5rem 0', color: '#333' }}>Update Profile</h3>
                    
                    {message && (
                        <div style={{ 
                            padding: '1rem', 
                            marginBottom: '1.5rem',
                            backgroundColor: message.includes('successfully') ? '#d4edda' : '#f8d7da',
                            color: message.includes('successfully') ? '#155724' : '#721c24',
                            border: `1px solid ${message.includes('successfully') ? '#c3e6cb' : '#f5c6cb'}`,
                            borderRadius: '8px'
                        }}>
                            {message}
                        </div>
                    )}
                    
                    <form onSubmit={handleSubmit}>
                        <div style={{ marginBottom: '1.5rem' }}>
                            <label style={{ 
                                display: 'block', 
                                marginBottom: '0.5rem', 
                                fontWeight: 'bold',
                                color: '#333'
                            }}>
                                Display Name:
                            </label>
                            <input
                                type="text"
                                value={profileData.display_name}
                                onChange={(e) => setProfileData({
                                    ...profileData, 
                                    display_name: e.target.value
                                })}
                                style={{
                                    width: '100%',
                                    padding: '0.75rem',
                                    border: '2px solid #e9ecef',
                                    borderRadius: '8px',
                                    fontSize: '1rem',
                                    maxWidth: '500px',
                                    transition: 'border-color 0.3s ease'
                                }}
                                onFocus={(e) => e.target.style.borderColor = '#007bff'}
                                onBlur={(e) => e.target.style.borderColor = '#e9ecef'}
                                required
                                disabled={isUpdating}
                            />
                        </div>
                        
                        <div style={{ marginBottom: '2rem' }}>
                            <label style={{ 
                                display: 'block', 
                                marginBottom: '0.5rem', 
                                fontWeight: 'bold',
                                color: '#333'
                            }}>
                                Email Address:
                            </label>
                            <input
                                type="email"
                                value={profileData.email}
                                onChange={(e) => setProfileData({
                                    ...profileData, 
                                    email: e.target.value
                                })}
                                style={{
                                    width: '100%',
                                    padding: '0.75rem',
                                    border: '2px solid #e9ecef',
                                    borderRadius: '8px',
                                    fontSize: '1rem',
                                    maxWidth: '500px',
                                    transition: 'border-color 0.3s ease'
                                }}
                                onFocus={(e) => e.target.style.borderColor = '#007bff'}
                                onBlur={(e) => e.target.style.borderColor = '#e9ecef'}
                                required
                                disabled={isUpdating}
                            />
                        </div>
                        
                        <button 
                            type="submit"
                            disabled={isUpdating}
                            style={{
                                padding: '0.75rem 2rem',
                                backgroundColor: isUpdating ? '#6c757d' : '#007bff',
                                color: 'white',
                                border: 'none',
                                borderRadius: '8px',
                                cursor: isUpdating ? 'not-allowed' : 'pointer',
                                fontWeight: 'bold',
                                fontSize: '1rem',
                                transition: 'background-color 0.3s ease'
                            }}
                            onMouseEnter={(e) => {
                                if (!isUpdating) e.target.style.backgroundColor = '#0056b3';
                            }}
                            onMouseLeave={(e) => {
                                if (!isUpdating) e.target.style.backgroundColor = '#007bff';
                            }}
                        >
                            {isUpdating ? 'Updating...' : 'Save Changes'}
                        </button>
                    </form>
                </div>
            </div>
        </div>
    );
}