import { getAuthToken } from './SessionManager';

// Store the session timeout handler function
let sessionTimeoutHandler = null;

// Register the session timeout handler from the context
export const registerSessionTimeoutHandler = (handler) => {
    sessionTimeoutHandler = handler;
};

// fetch wrapper with automatic 401 handling
export const apiRequest = async (url, options = {}) => {
    const token = getAuthToken();
    
    // Default headers
    const defaultHeaders = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    // Add authorization header if token exists
    if (token) {
        defaultHeaders.Authorization = `Bearer ${token}`;
    }
    
    // Enhanced options with defaults
    const enhancedOptions = {
        credentials: 'include', // Always include cookies for session management
        ...options,
        headers: defaultHeaders
    };
    
    try {
        console.log(`API Request: ${options.method || 'GET'} ${url}`);
        const response = await fetch(url, enhancedOptions);
        
        // Handle 401 responses globally
        if (response.status === 401) {
            console.log('401 Unauthorized detected - triggering session timeout');
            
            // Trigger session timeout if handler is registered
            if (sessionTimeoutHandler) {
                sessionTimeoutHandler();
            }
            
            // Return a rejected promise to stop further processing
            throw new Error('Session expired');
        }
        
        // Handle other error status codes
        if (!response.ok) {
            const errorText = await response.text();
            let errorMessage;
            
            try {
                const errorJson = JSON.parse(errorText);
                errorMessage = errorJson.error || errorJson.message || `HTTP ${response.status}`;
            } catch {
                errorMessage = errorText || `HTTP ${response.status}`;
            }
            
            throw new Error(errorMessage);
        }
        
        // Parse JSON response
        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        }
        
        // Return text for non-JSON responses
        return await response.text();
        
    } catch (error) {
        console.error(`API Error [${options.method || 'GET'} ${url}]:`, error.message);
        throw error;
    }
};

// Convenience methods
export const apiGet = (url, options = {}) => {
    return apiRequest(url, { ...options, method: 'GET' });
};

export const apiPost = (url, data, options = {}) => {
    return apiRequest(url, {
        ...options,
        method: 'POST',
        body: JSON.stringify(data)
    });
};

export const apiPut = (url, data, options = {}) => {
    return apiRequest(url, {
        ...options,
        method: 'PUT',
        body: JSON.stringify(data)
    });
};

export const apiDelete = (url, options = {}) => {
    return apiRequest(url, { ...options, method: 'DELETE' });
};

// Specific API endpoints for common operations
const API_BASE = 'http://localhost:3001/api';

export const authAPI = {
    login: (credentials) => apiPost(`${API_BASE}/auth/login`, credentials),
    logout: () => apiPost(`${API_BASE}/auth/logout`),
    register: (userData) => apiPost(`${API_BASE}/auth/register`, userData),
    verifyPermission: (permission) => apiGet(`${API_BASE}/auth/verify-permission/${permission}`),
    test: () => apiGet(`${API_BASE}/auth/test`)
};

export const userAPI = {
    getAll: () => apiGet(`${API_BASE}/users`),
    update: (id, data) => apiPut(`${API_BASE}/users/${id}`, data),
    updateRoles: (id, roleIds) => apiPut(`${API_BASE}/users/${id}/roles`, { roleIds }),
    delete: (id) => apiDelete(`${API_BASE}/users/${id}`)
};