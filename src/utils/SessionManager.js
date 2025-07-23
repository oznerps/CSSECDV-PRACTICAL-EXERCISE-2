// Session management with JWT token handling

const SESSION_KEY = 'auth_session';

export const setSession = (sessionData) => {
    try {
        const session = {
            user: sessionData.user,
            token: sessionData.token,
            timestamp: new Date().getTime(),
            expiresAt: sessionData.expiresAt || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        };

        localStorage.setItem(SESSION_KEY, JSON.stringify(session));
        console.log('Session set successfully');
        
    } catch (error) {
        console.error('Failed to set session:', error);
        clearSession();
    }
};

export const getSession = () => {
    try {
        const sessionStr = localStorage.getItem(SESSION_KEY);

        if (!sessionStr) {
            return null;
        }

        const sessionData = JSON.parse(sessionStr);
        
        // Check if session data is valid
        if (!sessionData.user || !sessionData.token) {
            clearSession();
            return null;
        }
        
        // Check if session is expired
        const now = new Date().getTime();
        const expiryTime = new Date(sessionData.expiresAt).getTime();
        
        if (now > expiryTime) {
            console.log('Session expired');
            clearSession();
            return null;
        }
        
        // Return user data with token for API calls
        return {
            ...sessionData.user,
            token: sessionData.token
        };
        
    } catch (error) {
        console.error('Error reading session:', error);
        clearSession();
        return null;
    }
};

export const getAuthToken = () => {
    try {
        const sessionStr = localStorage.getItem(SESSION_KEY);
        
        if (!sessionStr) {
            return null;
        }
        
        const sessionData = JSON.parse(sessionStr);
        
        // Check expiration
        const now = new Date().getTime();
        const expiryTime = new Date(sessionData.expiresAt).getTime();
        
        if (now > expiryTime) {
            clearSession();
            return null;
        }
        
        return sessionData.token;
        
    } catch (error) {
        console.error('Error getting auth token:', error);
        return null;
    }
};

export const updateSession = (updates) => {
    try {
        const currentSession = getSession();
        if (!currentSession) {
            return false;
        }
        
        const sessionStr = localStorage.getItem(SESSION_KEY);
        const sessionData = JSON.parse(sessionStr);
        
        const updatedSession = {
            ...sessionData,
            user: { ...sessionData.user, ...updates },
            timestamp: new Date().getTime()
        };
        
        localStorage.setItem(SESSION_KEY, JSON.stringify(updatedSession));
        return true;
        
    } catch (error) {
        console.error('Failed to update session:', error);
        return false;
    }
};

export const clearSession = () => {
    try {
        localStorage.removeItem(SESSION_KEY);
        console.log('Session cleared');
    } catch (error) {
        console.error('Error clearing session:', error);
    }
};

export const isAuthenticated = () => {
    const session = getSession();
    return session !== null && session.token !== null;
};

export const isSessionExpiring = (minutesThreshold = 5) => {
    try {
        const sessionStr = localStorage.getItem(SESSION_KEY);
        
        if (!sessionStr) {
            return false;
        }
        
        const sessionData = JSON.parse(sessionStr);
        const now = new Date().getTime();
        const expiryTime = new Date(sessionData.expiresAt).getTime();
        const thresholdTime = minutesThreshold * 60 * 1000;
        
        return (expiryTime - now) <= thresholdTime;
        
    } catch (error) {
        console.error('Error checking session expiration:', error);
        return false;
    }
};

// Refresh session token
export const refreshSessionToken = async () => {
    try {
        const currentToken = getAuthToken();
        
        if (!currentToken) {
            throw new Error('No valid token to refresh');
        }
        
        const response = await fetch('http://localhost:3001/api/auth/refresh', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${currentToken}`,
                'Content-Type': 'application/json',
            },
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Token refresh failed');
        }
        
        const data = await response.json();
        
        // Update session with new token
        const sessionStr = localStorage.getItem(SESSION_KEY);
        const sessionData = JSON.parse(sessionStr);
        
        const updatedSession = {
            ...sessionData,
            token: data.token,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
            timestamp: new Date().getTime()
        };
        
        localStorage.setItem(SESSION_KEY, JSON.stringify(updatedSession));
        
        return data.token;
        
    } catch (error) {
        console.error('Failed to refresh token:', error);
        clearSession();
        throw error;
    }
};