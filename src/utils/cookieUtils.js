// Cookie utility functions for session management

export const clearSessionCookie = () => {
    try {
        // Clear both possible cookie names (dev and production)
        const cookieNames = ['sessionid', '__Host-sessionid'];
        
        cookieNames.forEach(cookieName => {
            // Clear with different path and domain combinations to ensure removal
            const clearOptions = [
                `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`,
                `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; domain=localhost`,
                `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure`,
                `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; secure; samesite=strict`,
            ];
            
            clearOptions.forEach(cookieString => {
                document.cookie = cookieString;
            });
        });
        
        console.log('Session cookies cleared');
    } catch (error) {
        console.error('Error clearing session cookies:', error);
    }
};

export const hasSessionCookie = () => {
    try {
        const cookies = document.cookie.split(';');
        return cookies.some(cookie => {
            const name = cookie.trim().split('=')[0];
            return name === 'sessionid' || name === '__Host-sessionid';
        });
    } catch (error) {
        console.error('Error checking session cookie:', error);
        return false;
    }
};

export const getSessionCookieValue = () => {
    try {
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'sessionid' || name === '__Host-sessionid') {
                return value;
            }
        }
        return null;
    } catch (error) {
        console.error('Error getting session cookie value:', error);
        return null;
    }
};