import React from 'react';
import { formatDate, formatUserFriendlyDateTime } from '../utils/dateUtils';

const UserInfoCard = ({ user }) => {

    const getUserRoles = () => {
        if (!user || !user.roles) return [];
        return Array.isArray(user.roles) ? user.roles.map(role => 
            typeof role === 'string' ? role : role.name
        ) : [];
    };

    const getRoleBadgeColor = (role) => {
        switch (role.toLowerCase()) {
            case 'admin': return '#dc3545';
            case 'manager': return '#28a745';
            default: return '#007bff';
        }
    };

    return (
        <div style={{
            backgroundColor: 'white',
            padding: '2rem',
            borderRadius: '12px',
            boxShadow: '0 2px 12px rgba(0,0,0,0.1)',
            marginBottom: '2rem'
        }}>
            <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                marginBottom: '1.5rem',
                paddingBottom: '1rem',
                borderBottom: '2px solid #f8f9fa'
            }}>
                <div style={{
                    width: '60px',
                    height: '60px',
                    borderRadius: '50%',
                    backgroundColor: '#007bff',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: 'white',
                    fontSize: '1.5rem',
                    fontWeight: 'bold',
                    marginRight: '1rem'
                }}>
                    {user.display_name ? user.display_name.charAt(0).toUpperCase() : 
                     user.username ? user.username.charAt(0).toUpperCase() : '?'}
                </div>
                <div>
                    <h2 style={{ 
                        margin: '0 0 0.25rem 0', 
                        fontSize: '1.5rem',
                        color: '#333'
                    }}>
                        Welcome, {user.display_name || user.username}!
                    </h2>
                    <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                        {getUserRoles().map(role => (
                            <span 
                                key={role}
                                style={{
                                    backgroundColor: getRoleBadgeColor(role),
                                    color: 'white',
                                    padding: '0.25rem 0.75rem',
                                    borderRadius: '12px',
                                    fontSize: '0.8rem',
                                    fontWeight: 'bold',
                                    textTransform: 'uppercase'
                                }}
                            >
                                {role}
                            </span>
                        ))}
                    </div>
                </div>
            </div>

            <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                gap: '1rem'
            }}>
                <div>
                    <h4 style={{ margin: '0 0 0.75rem 0', color: '#666' }}>Account Information</h4>
                    <div style={{ fontSize: '0.95rem', lineHeight: '1.6' }}>
                        <p style={{ margin: '0.25rem 0' }}>
                            <strong>Username:</strong> {user.username || 'Not available'}
                        </p>
                        <p style={{ margin: '0.25rem 0' }}>
                            <strong>Email:</strong> {user.email || 'Not available'}
                        </p>
                        <p style={{ margin: '0.25rem 0' }}>
                            <strong>Display Name:</strong> {user.display_name || 'Not set'}
                        </p>
                    </div>
                </div>
                
                <div>
                    <h4 style={{ margin: '0 0 0.75rem 0', color: '#666' }}>Activity</h4>
                    <div style={{ fontSize: '0.95rem', lineHeight: '1.6' }}>
                        <p style={{ margin: '0.25rem 0' }}>
                            <strong>Member Since:</strong> {formatDate(user.created_at)}
                        </p>
                        <p style={{ margin: '0.25rem 0' }}>
                            <strong>Last Login:</strong> {formatUserFriendlyDateTime(user.last_login)}
                        </p>
                        <p style={{ margin: '0.25rem 0' }}>
                            <strong>Last Updated:</strong> {formatUserFriendlyDateTime(user.updated_at)}
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default UserInfoCard;