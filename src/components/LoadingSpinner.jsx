import React from 'react';

const LoadingSpinner = ({ 
    size = 'medium', 
    message = 'Loading...', 
    color = '#007bff',
    fullScreen = false 
}) => {
    const getSizeStyles = () => {
        switch (size) {
            case 'small': return { width: '24px', height: '24px', borderWidth: '2px' };
            case 'large': return { width: '48px', height: '48px', borderWidth: '4px' };
            default: return { width: '32px', height: '32px', borderWidth: '3px' };
        }
    };

    const sizeStyles = getSizeStyles();
    
    const spinnerStyle = {
        ...sizeStyles,
        border: `${sizeStyles.borderWidth} solid #f3f3f3`,
        borderTop: `${sizeStyles.borderWidth} solid ${color}`,
        borderRadius: '50%',
        animation: 'spin 1s linear infinite',
        margin: message ? '0 auto 1rem' : '0 auto'
    };

    const containerStyle = fullScreen ? {
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: 'rgba(255, 255, 255, 0.9)',
        zIndex: 9999
    } : {
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        alignItems: 'center',
        padding: '2rem',
        color: '#666'
    };

    return (
        <div style={containerStyle}>
            <div style={spinnerStyle}></div>
            {message && (
                <p style={{ 
                    margin: 0, 
                    fontSize: size === 'small' ? '0.8rem' : '1rem',
                    color: '#666'
                }}>
                    {message}
                </p>
            )}
            <style dangerouslySetInnerHTML={{
                __html: `
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                `
            }} />
        </div>
    );
};

export default LoadingSpinner;