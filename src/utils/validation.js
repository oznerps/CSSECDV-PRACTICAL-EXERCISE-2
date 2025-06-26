// Username validation utilities
export const validateUsername = (username) => {
    const errors = [];

    // Check length requirements (3-30 characters)
    if (!username || username.length < 3) {
        errors.push("Username must be at least 3 characters long");
    }
    if (username && username.length > 30) {
        errors.push("Username must be 30 characters or less");
    }

    // Check allowed characters (alphanumeric, underscore, hyphen only)
    const allowedPattern = /^[a-zA-Z0-9_-]+$/;
    if (username && !allowedPattern.test(username)) {
        errors.push("Username can only contain letters, numbers, hyphens, and underscores");
    }

    // Check for invalid starting/ending characters
    if (username && (username.startsWith('_') || username.startsWith('-') || 
                    username.endsWith('_') || username.endsWith('-'))) {
        errors.push("Username cannot start or end with special characters");
    }

    // Check for consecutive special characters
    if (username && /[_-]{2,}/.test(username)) {
        errors.push("Username cannot contain consecutive special characters");
    }

    // Check against reserved words
    const reservedWords = [
        'admin', 'administrator', 'root', 'superuser', 'moderator',
        'support', 'help', 'api', 'www', 'mail', 'email', 'system',
        'null', 'undefined', 'test', 'demo', 'guest'
    ];

    if (username && reservedWords.includes(username.toLowerCase())) {
        errors.push("This username is not available");
    }

    return {
        isValid: errors.length === 0,
        errors: errors
    };
};

// Email validation utilities
export const validateEmail = (email) => {
    const errors = [];

    // Check if email is provided
    if (!email || email.trim() === '') {
        errors.push("Email address is required");
        return { isValid: false, errors };
    }

    // Trim and normalize
    const normalizedEmail = email.trim().toLowerCase();

    // Check length limit (320 characters max per RFC standards)
    if (normalizedEmail.length > 320) {
        errors.push("Email address must not exceed 320 characters");
    }

    // Check for exactly one @ symbol
    const atCount = (normalizedEmail.match(/@/g) || []).length;
    if (atCount !== 1) {
        errors.push("Please enter a valid email address");
        return { isValid: false, errors };
    }

    // Split into local and domain parts
    const [localPart, domainPart] = normalizedEmail.split('@');

    // Validate local part (before @)
    if (!localPart || localPart.length === 0 || localPart.length > 64) {
        errors.push("Please enter a valid email address");
    }

    // Check local part format (alphanumeric, periods, hyphens only)
    const localPattern = /^[a-zA-Z0-9.-]+$/;
    if (localPart && !localPattern.test(localPart)) {
        errors.push("Please enter a valid email address");
    }

    // Check for consecutive dots
    if (localPart && /\.{2,}/.test(localPart)) {
        errors.push("Please enter a valid email address");
    }

    // Validate domain part (after @)
    if (!domainPart || domainPart.length === 0) {
        errors.push("Please enter a valid email address");
    }

    // Basic domain format check
    const domainPattern = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (domainPart && !domainPattern.test(domainPart)) {
        errors.push("Please enter a valid email address");
    }

    return {
        isValid: errors.length === 0,
        errors: errors,
        normalizedEmail: normalizedEmail
    };
};

// Password strength validation
export const validatePassword = (password, username = '', email = '') => {
    const errors = [];

    // Early return if password is not provided
    if (!password) {
        errors.push("Password is required");
        return {
            isValid: false,
            errors: errors
        };
    }

    // Convert to lowercase once at the beginning
    const passwordLower = password.toLowerCase();
    const usernameLower = username ? username.toLowerCase() : '';
    const emailLower = email ? email.toLowerCase() : '';

    // Check length requirements
    if (password.length < 8) {
        errors.push("Password must be at least 8 characters long");
    }
    if (password.length > 128) {
        errors.push("Password must not exceed 128 characters");
    }

    // Check against common passwords
    const commonPasswords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password123', 'admin', 'letmein', 'welcome', 'monkey',
        'dragon', 'master', 'shadow', 'football', 'baseball'
    ];

    if (commonPasswords.includes(passwordLower)) {
        errors.push("This password is too common");
    }

    // Check against username similarity
    if (username && passwordLower === usernameLower) {
        errors.push("Password cannot be the same as your username");
    }

    // Check against email similarity
    if (email) {
        // Method 1: Check against full email
        if (passwordLower === emailLower) {
            errors.push("Password cannot be the same as your email");
        }
        // Method 2: Check against email local part (before @)
        else if (email.includes('@')) {
            const emailLocalPart = email.split('@')[0];
            const emailLocalLower = emailLocalPart.toLowerCase();
            
            if (passwordLower === emailLocalLower) {
                errors.push("Password cannot be the same as your email");
            }
        }
    }

    // Check for sequential patterns
    const sequentialPatterns = [
        '123456', '654321', 'abcdef', 'fedcba',
        'qwerty', 'asdfgh', '111111', '000000'
    ];

    for (const pattern of sequentialPatterns) {
        if (passwordLower.includes(pattern)) {
            errors.push("Password cannot contain sequential characters");
            break;
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
};

// Input sanitization utilities
export const sanitizeInput = (input) => {
    if (!input) return '';

    // Remove leading/trailing whitespace
    let sanitized = input.trim();

    // Basic XSS prevention - escape HTML characters
    sanitized = sanitized
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');

    return sanitized;
};