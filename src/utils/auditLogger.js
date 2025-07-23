import fs from 'fs/promises';
import path from 'path';

const LOG_DIR = './logs';
const SECURITY_LOG = path.join(LOG_DIR, 'security.log');
const ACCESS_LOG = path.join(LOG_DIR, 'access.log');

// Ensure log directory exists
async function ensureLogDirectory() {
    try {
        await fs.access(LOG_DIR);
    } catch {
        await fs.mkdir(LOG_DIR, { recursive: true });
    }
}

// Generic log function
async function writeLog(logFile, logEntry) {
    try {
        await ensureLogDirectory();
        const timestamp = new Date().toISOString();
        const logLine = `[${timestamp}] ${JSON.stringify(logEntry)}\n`;
        await fs.appendFile(logFile, logLine);
    } catch (error) {
        console.error(`Failed to write to log file ${logFile}:`, error);
    }
}

// Security event logging
export async function logSecurityEvent(eventType, userId, details) {
    const logEntry = {
        type: 'SECURITY_EVENT',
        eventType,
        userId,
        details,
        timestamp: new Date().toISOString()
    };
    
    await writeLog(SECURITY_LOG, logEntry);
    console.log(`Security Event: ${eventType} - User: ${userId} - ${details}`);
}

// Authentication event logging
export async function logAuthEvent(eventType, userId, clientIP, details) {
    const logEntry = {
        type: 'AUTH_EVENT',
        eventType,
        userId,
        clientIP,
        details,
        timestamp: new Date().toISOString()
    };
    
    await writeLog(SECURITY_LOG, logEntry);
    
    // Also log to console for development
    if (eventType.includes('FAILED')) {
        console.warn(`Auth Event: ${eventType} - IP: ${clientIP} - ${details}`);
    } else {
        console.log(`Auth Event: ${eventType} - User: ${userId} - IP: ${clientIP}`);
    }
}

// Authorization failure logging
export async function logAuthorizationFailure(userId, requiredPermission, reason) {
    const logEntry = {
        type: 'AUTHORIZATION_FAILURE',
        userId,
        requiredPermission,
        reason,
        timestamp: new Date().toISOString()
    };
    
    await writeLog(SECURITY_LOG, logEntry);
    console.warn(`Authorization Failure: User ${userId} - Required: ${requiredPermission} - Reason: ${reason}`);
}

// Access attempt logging
export async function logAccessAttempt(identifier, clientIP, action) {
    const logEntry = {
        type: 'ACCESS_ATTEMPT',
        identifier,
        clientIP,
        action,
        timestamp: new Date().toISOString()
    };
    
    await writeLog(ACCESS_LOG, logEntry);
}

// Role change logging
export async function logRoleChange(adminUserId, targetUserId, oldRoles, newRoles) {
    const logEntry = {
        type: 'ROLE_CHANGE',
        adminUserId,
        targetUserId,
        oldRoles,
        newRoles,
        timestamp: new Date().toISOString()
    };
    
    await writeLog(SECURITY_LOG, logEntry);
    console.log(`Role Change: Admin ${adminUserId} changed roles for user ${targetUserId}`);
}

// Permission check logging (for sensitive operations)
export async function logPermissionCheck(userId, permission, granted, context) {
    const logEntry = {
        type: 'PERMISSION_CHECK',
        userId,
        permission,
        granted,
        context,
        timestamp: new Date().toISOString()
    };
    
    await writeLog(ACCESS_LOG, logEntry);
}

// User deletion logging
export async function logUserDeletion(adminUserId, deletedUser) {
    const logEntry = {
        type: 'USER_DELETION',
        adminUserId,
        deletedUser: {
            id: deletedUser.id,
            username: deletedUser.username,
            display_name: deletedUser.display_name,
            email: deletedUser.email
        },
        timestamp: new Date().toISOString()
    };
    
    await writeLog(SECURITY_LOG, logEntry);
    console.log(`User Deletion: Admin ${adminUserId} deleted user ${deletedUser.username} (${deletedUser.id})`);
}