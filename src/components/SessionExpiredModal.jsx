import React from 'react';
import { useSessionTimeout } from '../contexts/SessionTimeoutContext';

const SessionExpiredModal = () => {
    const { isTimeoutModalVisible } = useSessionTimeout();

    if (!isTimeoutModalVisible) {
        return null;
    }

    return (
        <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 10000,
            animation: 'fadeIn 0.3s ease-out'
        }}>
            <div style={{
                backgroundColor: 'white',
                borderRadius: '12px',
                padding: '32px',
                maxWidth: '450px',
                width: '90%',
                boxShadow: '0 10px 30px rgba(0, 0, 0, 0.3)',
                textAlign: 'center',
                animation: 'scaleIn 0.3s ease-out'
            }}>
                <div style={{
                    fontSize: '48px',
                    marginBottom: '16px'
                }}>
                    🔒
                </div>
                
                <h2 style={{
                    color: '#dc3545',
                    marginBottom: '16px',
                    fontSize: '24px',
                    fontWeight: 'bold'
                }}>
                    Session Expired
                </h2>
                
                <p style={{
                    color: '#666',
                    marginBottom: '24px',
                    fontSize: '16px',
                    lineHeight: '1.5'
                }}>
                    Your session has timed out for security reasons. You will be redirected to the login page.
                </p>
                
                <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '8px',
                    color: '#007bff',
                    fontSize: '14px'
                }}>
                    <div className="spinner" style={{
                        width: '16px',
                        height: '16px',
                        border: '2px solid #e3f2fd',
                        borderTop: '2px solid #007bff',
                        borderRadius: '50%',
                        animation: 'spin 1s linear infinite'
                    }}></div>
                    Redirecting to login...
                </div>
            </div>
            
            <style jsx>{`
                @keyframes fadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                
                @keyframes scaleIn {
                    from {
                        transform: scale(0.9);
                        opacity: 0;
                    }
                    to {
                        transform: scale(1);
                        opacity: 1;
                    }
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            `}</style>
        </div>
    );
};

export default SessionExpiredModal;