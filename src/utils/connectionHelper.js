// Utility functions to fix connection issues without restarting servers

export const clearStaleData = () => {
    console.log('Clearing stale browser data...');
    localStorage.clear();
    sessionStorage.clear();
    
    // Clear any cached fetch requests
    if ('caches' in window) {
        caches.keys().then(names => {
            names.forEach(name => {
                caches.delete(name);
            });
        });
    }
    
    console.log('Browser data cleared');
};

export const testServerConnection = async () => {
    try {
        console.log('Testing server connection...');
        const response = await fetch('http://localhost:3001/health', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Server connection OK:', data);
            return true;
        } else {
            console.error('Server responded with error:', response.status);
            return false;
        }
    } catch (error) {
        console.error('Server connection failed:', error);
        return false;
    }
};

export const refreshAuthToken = async () => {
    try {
        const sessionStr = localStorage.getItem('auth_session');
        if (!sessionStr) {
            console.log('No session found to refresh');
            return false;
        }
        
        const session = JSON.parse(sessionStr);
        if (!session.token) {
            console.log('No token found to refresh');
            return false;
        }
        
        console.log('Attempting to refresh auth token...');
        const response = await fetch('http://localhost:3001/api/auth/refresh', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${session.token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.success && data.token) {
                session.token = data.token;
                session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
                session.timestamp = new Date().getTime();
                localStorage.setItem('auth_session', JSON.stringify(session));
                console.log('Token refreshed successfully');
                return true;
            }
        }
        
        console.log('Token refresh failed');
        return false;
    } catch (error) {
        console.error('Error refreshing token:', error);
        return false;
    }
};

export const fixConnectionIssues = async () => {
    console.log('Starting connection fix procedure...');
    
    // Step 1: Test if server is reachable
    const serverOK = await testServerConnection();
    if (!serverOK) {
        console.log('Server is not reachable');
        return false;
    }
    
    // Step 2: Try to refresh token
    const tokenRefreshed = await refreshAuthToken();
    if (tokenRefreshed) {
        console.log('Token refreshed, connection should work now');
        return true;
    }
    
    // Step 3: Clear stale data and force re-authentication
    console.log('Clearing stale data...');
    clearStaleData();
    
    console.log('Connection fix complete. Please log in again.');
    return true;
};

// Quick fix function that can be called from console
export const quickFix = () => {
    console.log('Running quick connection fix...');
    
    fixConnectionIssues().then((success) => {
        if (success) {
            console.log('Fix applied! Try your action again.');
            // Optionally reload the page
            if (confirm('Fix applied! Reload the page to see changes?')) {
                window.location.reload();
            }
        } else {
            console.log('Fix failed. You may need to restart the servers.');
        }
    });
};

// Auto-fix wrapper for API calls
export const withAutoFix = async (apiCall, maxRetries = 1) => {
    try {
        return await apiCall();
    } catch (error) {
        if ((error.message.includes('Failed to fetch') || 
            error.message.includes('CORS')) && maxRetries > 0) {
            
            console.log('API call failed, attempting auto-fix...');
            const fixApplied = await fixConnectionIssues();
            
            if (fixApplied) {
                console.log('Retrying API call after fix...');
                return await withAutoFix(apiCall, maxRetries - 1);
            }
        }
        throw error;
    }
};

// Make functions available globally for console access
if (typeof window !== 'undefined') {
    window.quickFix = quickFix;
    window.testServer = testServerConnection;
    window.clearStale = clearStaleData;
    window.refreshToken = refreshAuthToken;
}