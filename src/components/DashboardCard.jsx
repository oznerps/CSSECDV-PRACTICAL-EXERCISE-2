import React from 'react';
import { Link } from 'react-router-dom';

const DashboardCard = ({ 
    title, 
    description, 
    icon, 
    linkTo, 
    backgroundColor = '#007bff', 
    onClick,
    disabled = false 
}) => {
    const cardStyle = {
        padding: '1.5rem',
        backgroundColor: disabled ? '#e9ecef' : backgroundColor,
        color: disabled ? '#6c757d' : 'white',
        borderRadius: '12px',
        textDecoration: 'none',
        display: 'block',
        transition: 'all 0.3s ease',
        border: 'none',
        cursor: disabled ? 'not-allowed' : 'pointer',
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        position: 'relative',
        overflow: 'hidden'
    };

    const hoverStyle = disabled ? {} : {
        transform: 'translateY(-2px)',
        boxShadow: '0 4px 16px rgba(0,0,0,0.2)'
    };

    const content = (
        <div style={{ position: 'relative', zIndex: 1 }}>
            <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                marginBottom: '0.5rem' 
            }}>
                <span style={{ fontSize: '1.5rem', marginRight: '0.75rem' }}>
                    {icon}
                </span>
                <h3 style={{ 
                    margin: 0, 
                    fontSize: '1.25rem',
                    fontWeight: 'bold' 
                }}>
                    {title}
                </h3>
            </div>
            <p style={{ 
                margin: 0, 
                fontSize: '0.95rem',
                lineHeight: '1.4',
                opacity: disabled ? 0.6 : 0.9
            }}>
                {description}
            </p>
        </div>
    );

    if (disabled) {
        return (
            <div style={cardStyle}>
                {content}
            </div>
        );
    }

    if (linkTo) {
        return (
            <Link 
                to={linkTo} 
                style={cardStyle}
                onMouseEnter={(e) => {
                    Object.assign(e.target.style, hoverStyle);
                }}
                onMouseLeave={(e) => {
                    e.target.style.transform = 'translateY(0)';
                    e.target.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
                }}
            >
                {content}
            </Link>
        );
    }

    return (
        <button 
            style={cardStyle}
            onClick={onClick}
            onMouseEnter={(e) => {
                Object.assign(e.target.style, hoverStyle);
            }}
            onMouseLeave={(e) => {
                e.target.style.transform = 'translateY(0)';
                e.target.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
            }}
        >
            {content}
        </button>
    );
};

export default DashboardCard;