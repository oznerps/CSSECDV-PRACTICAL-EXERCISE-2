import React, { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAuthToken, clearSession, isAuthenticated } from '../utils/SessionManager';
import { clearSessionCookie } from '../utils/cookieUtils';

const SessionTimeoutContext = createContext({});

export const useSessionTimeout = () => {
    const context = useContext(SessionTimeoutContext);
    if (!context) {
        throw new Error('useSessionTimeout must be used within a SessionTimeoutProvider');
    }
    return context;
};

export const SessionTimeoutProvider = ({ children }) => {
    const navigate = useNavigate();
    const [sessionState, setSessionState] = useState({
        isAuthenticated: false,
        isWarningVisible: false,
        isTimeoutModalVisible: false,
        warningCount: 0
    });

    // Session timeout configuration (adjusts based on server timeout setting)
    const SESSION_TIMEOUT = 60000; // 1 minute (matches server.js line 366)
    const WARNING_TIME = 50000; // 50 seconds (10 seconds before timeout)

    const handleSessionExpired = useCallback(() => {
        console.log('Session has expired');
        
        // Clear local session data and cookies
        clearSession();
        clearSessionCookie();
        
        // Update session state
        setSessionState(prev => ({
            ...prev,
            isAuthenticated: false,
            isWarningVisible: false,
            isTimeoutModalVisible: true
        }));
        
        // Clear any existing timers
        clearTimeout(warningTimerRef.current);
        clearTimeout(timeoutTimerRef.current);
        
        // Redirect after showing modal briefly
        setTimeout(() => {
            setSessionState(prev => ({ ...prev, isTimeoutModalVisible: false }));
            navigate('/login', { replace: true });
        }, 3000);
    }, [navigate]);

    const handleSessionWarning = useCallback(() => {
        console.log('Session warning: expires in 10 seconds');
        setSessionState(prev => ({
            ...prev,
            isWarningVisible: true,
            warningCount: prev.warningCount + 1
        }));
        
        // Hide warning after 5 seconds
        setTimeout(() => {
            setSessionState(prev => ({ ...prev, isWarningVisible: false }));
        }, 5000);
    }, []);

    const handleForceLogout = useCallback(async () => {
        console.log('Force logout triggered by 401 response');
        
        try {
            const token = getAuthToken();
            if (token) {
                // Attempt server-side logout
                await fetch('http://localhost:3001/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include'
                });
            }
        } catch (error) {
            console.log('Server logout failed, proceeding with client cleanup');
        }
        
        // Always clear cookies and session data
        clearSession();
        clearSessionCookie();
        
        // Force session expired flow
        handleSessionExpired();
    }, [handleSessionExpired]);

    // Timer references
    const warningTimerRef = React.useRef(null);
    const timeoutTimerRef = React.useRef(null);
    const sessionCheckIntervalRef = React.useRef(null);

    const startSessionTimers = useCallback(() => {
        // Clear any existing timers
        clearTimeout(warningTimerRef.current);
        clearTimeout(timeoutTimerRef.current);
        
        console.log('Starting session timers');
        
        // Set warning timer
        warningTimerRef.current = setTimeout(() => {
            handleSessionWarning();
        }, WARNING_TIME);
        
        // Set timeout timer
        timeoutTimerRef.current = setTimeout(() => {
            handleSessionExpired();
        }, SESSION_TIMEOUT);
    }, [handleSessionWarning, handleSessionExpired, WARNING_TIME, SESSION_TIMEOUT]);

    const resetSessionTimers = useCallback(() => {
        if (isAuthenticated()) {
            console.log('Resetting session timers');
            startSessionTimers();
        }
    }, [startSessionTimers]);

    const stopSessionTimers = useCallback(() => {
        console.log('Stopping session timers');
        clearTimeout(warningTimerRef.current);
        clearTimeout(timeoutTimerRef.current);
        clearInterval(sessionCheckIntervalRef.current);
    }, []);

    // Initialize session monitoring
    useEffect(() => {
        const checkAuthState = () => {
            const authenticated = isAuthenticated();
            setSessionState(prev => ({
                ...prev,
                isAuthenticated: authenticated
            }));
            
            if (authenticated) {
                startSessionTimers();
            } else {
                stopSessionTimers();
            }
        };

        // Initial check
        checkAuthState();

        // Monitor localStorage changes (for cross-tab synchronization)
        const handleStorageChange = (e) => {
            if (e.key === 'auth_session') {
                checkAuthState();
            }
        };

        // Periodic session validation (every 30 seconds, less aggressive)
        sessionCheckIntervalRef.current = setInterval(() => {
            if (!isAuthenticated() && sessionState.isAuthenticated) {
                handleSessionExpired();
            }
        }, 30000);

        window.addEventListener('storage', handleStorageChange);

        return () => {
            stopSessionTimers();
            window.removeEventListener('storage', handleStorageChange);
        };
    }, [startSessionTimers, stopSessionTimers, handleSessionExpired, sessionState.isAuthenticated]);

    const contextValue = {
        ...sessionState,
        resetSessionTimers,
        handleForceLogout,
        dismissWarning: () => setSessionState(prev => ({ ...prev, isWarningVisible: false })),
        dismissTimeoutModal: () => setSessionState(prev => ({ ...prev, isTimeoutModalVisible: false }))
    };

    return (
        <SessionTimeoutContext.Provider value={contextValue}>
            {children}
        </SessionTimeoutContext.Provider>
    );
};