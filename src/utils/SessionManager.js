// Simple session management using localStorage

const SESSION_KEY = 'auth_session';

export const setSession = (userData) => {
    const sessionData = {
    user: userData,
    timestamp: new Date().getTime(),
    expiresAt: new Date().getTime() + (24 * 60 * 60 * 1000) // 24 hours
    };

    localStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
};

export const getSession = () => {
    const sessionStr = localStorage.getItem(SESSION_KEY);

    if (!sessionStr) {
        return null;
    }

    try {
        const sessionData = JSON.parse(sessionStr);
    
    // Check if session is expired
        if (new Date().getTime() > sessionData.expiresAt) {
            clearSession();
        return null;
}
    
    return sessionData.user;
    } catch (error) {
    clearSession();
    return null;
    }
};

export const clearSession = () => {
    localStorage.removeItem(SESSION_KEY);
};

export const isAuthenticated = () => {
    return getSession() !== null;
};