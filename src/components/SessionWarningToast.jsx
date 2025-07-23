import React from 'react';
import { useSessionTimeout } from '../contexts/SessionTimeoutContext';

const SessionWarningToast = () => {
    const { isWarningVisible, dismissWarning } = useSessionTimeout();

    if (!isWarningVisible) {
        return null;
    }

    return (
        <div style={{
            position: 'fixed',
            top: '20px',
            right: '20px',
            backgroundColor: '#fff3cd',
            border: '1px solid #ffeaa7',
            borderRadius: '8px',
            padding: '16px 20px',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
            zIndex: 9999,
            maxWidth: '400px',
            animation: 'slideInRight 0.3s ease-out'
        }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{
                    fontSize: '24px',
                    color: '#f39c12'
                }}>
                    ⚠️
                </div>
                <div style={{ flex: 1 }}>
                    <div style={{
                        fontWeight: 'bold',
                        color: '#856404',
                        marginBottom: '4px'
                    }}>
                        Session Expiring Soon
                    </div>
                    <div style={{
                        color: '#856404',
                        fontSize: '14px'
                    }}>
                        Your session will expire in 10 seconds. You will be redirected to login.
                    </div>
                </div>
                <button
                    onClick={dismissWarning}
                    style={{
                        background: 'none',
                        border: 'none',
                        fontSize: '18px',
                        color: '#856404',
                        cursor: 'pointer',
                        padding: '4px',
                        borderRadius: '4px',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center'
                    }}
                    title="Dismiss"
                >
                    ✕
                </button>
            </div>
            
            <style jsx>{`
                @keyframes slideInRight {
                    from {
                        transform: translateX(100%);
                        opacity: 0;
                    }
                    to {
                        transform: translateX(0);
                        opacity: 1;
                    }
                }
            `}</style>
        </div>
    );
};

export default SessionWarningToast;