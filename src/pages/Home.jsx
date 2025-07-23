import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import LoadingSpinner from '../components/LoadingSpinner';

const Home = () => {
    const { user, loading } = useAuth();

    if (loading) {
        return <LoadingSpinner size="large" message="Loading..." />;
    }

    return (
        <div style={{
            minHeight: '100vh',
            backgroundColor: '#f8f9fa',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '2rem 1rem'
        }}>
            <div style={{
                backgroundColor: 'white',
                padding: '3rem',
                borderRadius: '12px',
                boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
                textAlign: 'center',
                maxWidth: '600px',
                width: '100%'
            }}>
                <h1 style={{
                    fontSize: '2.5rem',
                    color: '#333',
                    marginBottom: '1rem',
                    fontWeight: 'bold'
                }}>
                    Welcome to the Website
                </h1>
                
                {user && (
                    <p style={{
                        fontSize: '1.2rem',
                        color: '#666',
                        marginBottom: '2rem'
                    }}>
                        Hello, <strong>{user.display_name || user.username}</strong>! 
                        You have successfully logged in.
                    </p>
                )}

                <p style={{
                    fontSize: '1rem',
                    color: '#888',
                    marginBottom: '2.5rem',
                    lineHeight: '1.6'
                }}>
                    This is a secure application with role-based access control. 
                    Use the dashboard to access features based on your permissions.
                </p>

                <Link 
                    to="/dashboard"
                    style={{
                        display: 'inline-block',
                        padding: '1rem 2rem',
                        backgroundColor: '#007bff',
                        color: 'white',
                        textDecoration: 'none',
                        borderRadius: '8px',
                        fontSize: '1.1rem',
                        fontWeight: 'bold',
                        transition: 'background-color 0.3s ease'
                    }}
                    onMouseEnter={(e) => e.target.style.backgroundColor = '#0056b3'}
                    onMouseLeave={(e) => e.target.style.backgroundColor = '#007bff'}
                >
                    Go to Dashboard
                </Link>
            </div>
        </div>
    );
};

export default Home;