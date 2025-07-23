// Centralized date/time formatting utilities with proper timezone handling

export const formatDate = (dateString, options = {}) => {
    if (!dateString) return 'Not available';
    
    try {
        const date = new Date(dateString);
        
        if (isNaN(date.getTime())) {
            return 'Not available';
        }
        
        const defaultOptions = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            ...options
        };
        
        return date.toLocaleDateString(undefined, defaultOptions);
    } catch (error) {
        console.error('Error formatting date:', error);
        return 'Not available';
    }
};

export const formatDateTime = (dateString, options = {}) => {
    if (!dateString) return 'Never';
    
    try {
        const date = new Date(dateString);
        
        if (isNaN(date.getTime())) {
            return 'Never';
        }
        
        const defaultOptions = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false, // Use 24-hour format
            ...options
        };
        
        return date.toLocaleString(undefined, defaultOptions);
    } catch (error) {
        console.error('Error formatting datetime:', error);
        return 'Never';
    }
};

export const formatRelativeTime = (dateString) => {
    if (!dateString) return 'Never';
    
    try {
        const date = new Date(dateString);
        const now = new Date();
        
        if (isNaN(date.getTime())) {
            return 'Never';
        }
        
        const diffMs = now - date;
        const diffMinutes = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMinutes / 60);
        const diffDays = Math.floor(diffHours / 24);
        
        if (diffMinutes < 1) {
            return 'Just now';
        } else if (diffMinutes < 60) {
            return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ago`;
        } else if (diffHours < 24) {
            return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
        } else if (diffDays < 7) {
            return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
        } else {
            // For older dates, show the actual date
            return formatDateTime(dateString, { 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
        }
    } catch (error) {
        console.error('Error formatting relative time:', error);
        return 'Never';
    }
};

export const formatTimeOnly = (dateString, options = {}) => {
    if (!dateString) return 'Never';
    
    try {
        const date = new Date(dateString);
        
        if (isNaN(date.getTime())) {
            return 'Never';
        }
        
        const defaultOptions = {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false, // Use 24-hour format
            ...options
        };
        
        return date.toLocaleTimeString(undefined, defaultOptions);
    } catch (error) {
        console.error('Error formatting time:', error);
        return 'Never';
    }
};

export const getCurrentTimestamp = () => {
    return new Date().toISOString();
};

export const isToday = (dateString) => {
    if (!dateString) return false;
    
    try {
        const date = new Date(dateString);
        const today = new Date();
        
        return date.toDateString() === today.toDateString();
    } catch {
        return false;
    }
};

export const formatUserFriendlyDateTime = (dateString) => {
    if (!dateString) return 'Never';
    
    try {
        const date = new Date(dateString);
        
        if (isNaN(date.getTime())) {
            return 'Never';
        }
        
        // Get user's timezone for more accurate display
        const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        
        if (isToday(dateString)) {
            return `Today at ${formatTimeOnly(dateString, { timeZone })}`;
        } else {
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            
            if (date.toDateString() === yesterday.toDateString()) {
                return `Yesterday at ${formatTimeOnly(dateString, { timeZone })}`;
            } else {
                return formatDateTime(dateString, {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZone
                });
            }
        }
    } catch (error) {
        console.error('Error formatting user-friendly datetime:', error);
        return 'Never';
    }
};