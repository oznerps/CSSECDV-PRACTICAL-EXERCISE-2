import { supabase } from '../supabaseClient.js';
import { hashPassword, verifyPassword } from './passwordUtils.js';
import { validateUsername, validateEmail, validatePassword, sanitizeInput } from './validation.js';

export const registerUser = async (userData) => {
    try {
        const { username, displayName, email, password } = userData;

        // Sanitize all inputs first
        const sanitizedUsername = sanitizeInput(username);
        const sanitizedDisplayName = sanitizeInput(displayName);
        const sanitizedEmail = sanitizeInput(email);

        // Validate username
        const usernameValidation = validateUsername(sanitizedUsername);
        if (!usernameValidation.isValid) {
            throw new Error(usernameValidation.errors[0]);
        }

        // Validate email
        const emailValidation = validateEmail(sanitizedEmail);
        if (!emailValidation.isValid) {
            throw new Error(emailValidation.errors[0]);
        }

        // Validate password
        const passwordValidation = validatePassword(password, sanitizedUsername, sanitizedEmail);
        if (!passwordValidation.isValid) {
            throw new Error(passwordValidation.errors[0]);
        }

        // Check for existing username (case-insensitive) - FIXED QUERY
        const { data: existingUsers } = await supabase
            .from('users')
            .select('id')
            .eq('username', sanitizedUsername.toLowerCase());
        
        if (existingUsers && existingUsers.length > 0) {
            throw new Error('Username already exists');
        }

        // Check for existing email (case-insensitive) - FIXED QUERY
        const { data: existingEmails } = await supabase
            .from('users')
            .select('id')
            .eq('email', emailValidation.normalizedEmail);
        
        if (existingEmails && existingEmails.length > 0) {
            throw new Error('An account with this email already exists');
        }

        // Hash password using the imported function
        const passwordHash = await hashPassword(password);
        
        // Insert user
        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert({
                username: sanitizedUsername.toLowerCase(),
                display_name: sanitizedDisplayName,
                email: emailValidation.normalizedEmail,
                password_hash: passwordHash,
                hash_algorithm: 'bcrypt'
            })
            .select()
            .single();
        
        if (insertError) {
            throw new Error(`Registration failed: ${insertError.message}`);
        }
        
        // Assign default 'user' role
        try {
            const defaultRole = await getRoleByName('user');
            await assignUserRole(newUser.id, defaultRole.id);
        } catch (roleError) {
            console.error('Warning: Could not assign default role:', roleError);
            // Don't fail registration if role assignment fails
        }
        
        return newUser;
        
    } catch (error) {
        throw error;
    }
};

// Function to authenticate a user (login) - FIXED WITH PROPER QUERIES
export const authenticateUser = async (identifier, password) => {
    try {
        // Sanitize input
        const sanitizedIdentifier = sanitizeInput(identifier);

        if (!sanitizedIdentifier || !password) {
            throw new Error('Invalid username/email or password');
        }

        // Determine if identifier is email or username
        const isEmail = sanitizedIdentifier.includes('@');

        //Use proper Supabase query syntax
        let query;
        if (isEmail) {
            // Search by email (case-insensitive)
            query = supabase
                .from('users')
                .select('*')
                .eq('email', sanitizedIdentifier.toLowerCase());
        } else {
            // Search by username (case-insensitive)
            query = supabase
                .from('users')
                .select('*')
                .eq('username', sanitizedIdentifier.toLowerCase());
        }

        const { data: users, error } = await query;

        // Generic error message to prevent user enumeration
        if (error || !users || users.length === 0) {
            throw new Error('Invalid username/email or password');
        }

        const user = users[0]; // Get the first (and should be only) user

        // Verify password
        const isPasswordValid = await verifyPassword(password, user.password_hash);

        if (!isPasswordValid) {
            throw new Error('Invalid username/email or password');
        }

        // Get user roles and permissions
        const userRoles = await getUserRoles(user.id);
        const userPermissions = await getUserPermissions(user.id);

        // Update last login timestamp
        await supabase
            .from('users')
            .update({ last_login: new Date().toISOString() })
            .eq('id', user.id);

        // Return user data (without password hash) with roles and permissions
        const { password_hash, ...userWithoutPassword } = user;
        
        return {
            ...userWithoutPassword,
            roles: userRoles,
            permissions: userPermissions
        };

    } catch (error) {
        console.error('Authentication error:', error);
        throw error;
    }
};

// RBAC functions
export async function getRoleByName(roleName) {
    const { data, error } = await supabase
        .from('roles')
        .select('*')
        .eq('name', roleName)
        .single();
    
    if (error) {
        throw new Error(`Role lookup failed: ${error.message}`);
    }
    
    return data;
}

/**
 * Assign role to user
 */
export async function assignUserRole(userId, roleId) {
    const { error } = await supabase
        .from('user_roles')
        .insert({ user_id: userId, role_id: roleId });
    
    if (error) {
        throw new Error(`Role assignment failed: ${error.message}`);
    }
}

/**
 * Get user roles
 */
export async function getUserRoles(userId) {
    const { data, error } = await supabase
        .from('user_roles')
        .select(`
            roles (
                id,
                name,
                description
            )
        `)
        .eq('user_id', userId);
    
    if (error) {
        console.error('Error fetching user roles:', error);
        return []; // Return empty array instead of throwing
    }
    
    return data ? data.map(item => item.roles).filter(Boolean) : [];
}

/**
 * Get user permissions through roles
 */
export async function getUserPermissions(userId) {
    const { data, error } = await supabase
        .from('user_roles')
        .select(`
            roles!inner (
                role_permissions!inner (
                    permissions!inner (
                        name
                    )
                )
            )
        `)
        .eq('user_id', userId);
    
    if (error) {
        console.error('Error fetching user permissions:', error);
        return []; // Return empty array instead of throwing
    }
    
    // Flatten the nested structure to get permission names
    const permissions = new Set();
    if (data) {
        data.forEach(userRole => {
            if (userRole.roles && userRole.roles.role_permissions) {
                userRole.roles.role_permissions.forEach(rolePermission => {
                    if (rolePermission.permissions) {
                        permissions.add(rolePermission.permissions.name);
                    }
                });
            }
        });
    }
    
    return Array.from(permissions);
}

/**
 * Check if user has specific permission
 */
export async function userHasPermission(userId, requiredPermission) {
    try {
        const permissions = await getUserPermissions(userId);
        return permissions.includes(requiredPermission);
    } catch (error) {
        console.error('Permission check failed:', error);
        return false;
    }
}

/**
 * Check if user has specific role
 */
export async function userHasRole(userId, roleName) {
    try {
        const roles = await getUserRoles(userId);
        return roles.some(role => role.name === roleName);
    } catch (error) {
        console.error('Role check failed:', error);
        return false;
    }
}

/**
 * Remove all user roles
 */
export async function removeUserRoles(userId) {
    const { error } = await supabase
        .from('user_roles')
        .delete()
        .eq('user_id', userId);
    
    if (error) {
        throw new Error(`Failed to remove user roles: ${error.message}`);
    }
}

/**
 * Update user roles (admin function)
 */
export async function updateUserRoles(userId, roleIds) {
    // Remove existing roles
    await removeUserRoles(userId);
    
    // Assign new roles
    for (const roleId of roleIds) {
        await assignUserRole(userId, roleId);
    }
}

/**
 * Get all users with their roles (admin function)
 */
export async function getAllUsersWithRoles() {
    const { data, error } = await supabase
        .from('users')
        .select(`
            id,
            username,
            display_name,
            email,
            created_at,
            last_login,
            user_roles (
                roles (
                    id,
                    name,
                    description
                )
            )
        `);
    
    if (error) {
        throw new Error(`Failed to fetch users: ${error.message}`);
    }
    
    return data.map(user => ({
        ...user,
        roles: user.user_roles ? user.user_roles.map(ur => ur.roles).filter(Boolean) : []
    }));
}

/**
 * Get all available roles
 */
export async function getAllRoles() {
    const { data, error } = await supabase
        .from('roles')
        .select('*')
        .order('name');
    
    if (error) {
        throw new Error(`Failed to fetch roles: ${error.message}`);
    }
    
    return data || [];
}

/**
 * Check if user can assign specific roles
 */
export async function canUserAssignRole(currentUserId, targetRoleId) {
    try {
        // Get current user's roles
        const currentUserRoles = await getUserRoles(currentUserId);
        
        // Get the target role details
        const { data: targetRole, error } = await supabase
            .from('roles')
            .select('*')
            .eq('id', targetRoleId)
            .single();
        
        if (error) {
            console.error('Error fetching target role:', error);
            return false;
        }
        
        // Admin can assign any role
        if (currentUserRoles.some(role => role.name === 'admin')) {
            return true;
        }
        
        // Manager can assign 'user' role but not 'admin' or 'manager'
        if (currentUserRoles.some(role => role.name === 'manager')) {
            return targetRole.name === 'user';
        }
        
        // Regular users cannot assign any roles
        return false;
        
    } catch (error) {
        console.error('Error checking role assignment permission:', error);
        return false;
    }
}

/**
 * Enhanced role update with comprehensive error handling and validation
 */
export async function updateUserRolesSecure(currentUserId, targetUserId, roleIds) {
    // Start a transaction-like operation
    let oldRoles = [];
    
    try {
        // Prevent self-modification for safety
        if (currentUserId === targetUserId) {
            throw new Error('Cannot modify your own roles');
        }
        
        // Get current roles for logging
        oldRoles = await getUserRoles(targetUserId);
        
        // Validate all role assignments before making changes
        for (const roleId of roleIds) {
            const canAssign = await canUserAssignRole(currentUserId, roleId);
            if (!canAssign) {
                throw new Error(`Insufficient permission to assign role ${roleId}`);
            }
        }
        
        // Validate that target user exists
        const { data: targetUser, error: userError } = await supabase
            .from('users')
            .select('id, username')
            .eq('id', targetUserId)
            .single();
        
        if (userError || !targetUser) {
            throw new Error('Target user not found');
        }
        
        // Remove existing roles
        const { error: removeError } = await supabase
            .from('user_roles')
            .delete()
            .eq('user_id', targetUserId);
        
        if (removeError) {
            throw new Error(`Failed to remove existing roles: ${removeError.message}`);
        }
        
        // Add new roles
        if (roleIds.length > 0) {
            const roleAssignments = roleIds.map(roleId => ({
                user_id: targetUserId,
                role_id: roleId
            }));
            
            const { error: insertError } = await supabase
                .from('user_roles')
                .insert(roleAssignments);
            
            if (insertError) {
                // Try to restore old roles if possible
                try {
                    if (oldRoles.length > 0) {
                        const restoreAssignments = oldRoles.map(role => ({
                            user_id: targetUserId,
                            role_id: role.id
                        }));
                        await supabase.from('user_roles').insert(restoreAssignments);
                    }
                } catch (restoreError) {
                    console.error('Failed to restore roles after error:', restoreError);
                }
                
                throw new Error(`Failed to assign new roles: ${insertError.message}`);
            }
        }
        
        // Get new roles for logging
        const newRoles = await getUserRoles(targetUserId);
        
        // Log the role change (import this function in server.js)
        try {
            const { logRoleChange } = await import('./auditLogger.js');
            await logRoleChange(currentUserId, targetUserId, oldRoles, newRoles);
        } catch (logError) {
            console.error('Logging error:', logError);
            // Don't fail the operation if logging fails
        }
        
        return {
            success: true,
            oldRoles,
            newRoles
        };
        
    } catch (error) {
        console.error('Error in updateUserRolesSecure:', error);
        throw error;
    }
}

/**
 * Get user by ID with roles and permissions
 */
export async function getUserWithRolesAndPermissions(userId) {
    try {
        const { data: user, error } = await supabase
            .from('users')
            .select(`
                id,
                username,
                display_name,
                email,
                created_at,
                last_login,
                user_roles (
                    roles (
                        id,
                        name,
                        description
                    )
                )
            `)
            .eq('id', userId)
            .single();
        
        if (error) {
            throw new Error(`Failed to fetch user: ${error.message}`);
        }
        
        const roles = user.user_roles ? user.user_roles.map(ur => ur.roles).filter(Boolean) : [];
        const permissions = await getUserPermissions(userId);
        
        return {
            ...user,
            roles,
            permissions
        };
        
    } catch (error) {
        throw error;
    }
}

/**
 * role assignment with validation
 */
export async function assignUserRoleSecure(currentUserId, targetUserId, roleId) {
    try {
        // Check permission to assign this role
        const canAssign = await canUserAssignRole(currentUserId, roleId);
        if (!canAssign) {
            throw new Error('Insufficient permission to assign this role');
        }
        
        // Check if role assignment already exists
        const { data: existing } = await supabase
            .from('user_roles')
            .select('id')
            .eq('user_id', targetUserId)
            .eq('role_id', roleId)
            .single();
        
        if (existing) {
            throw new Error('User already has this role');
        }
        
        // Assign the role
        const { error } = await supabase
            .from('user_roles')
            .insert({ user_id: targetUserId, role_id: roleId });
        
        if (error) {
            throw new Error(`Role assignment failed: ${error.message}`);
        }
        
        return { success: true };
        
    } catch (error) {
        throw error;
    }
}

/**
 * Delete user securely with permission checks
 */
export async function deleteUserSecure(currentUserId, targetUserId) {
    try {
        // Prevent self-deletion for safety
        if (currentUserId === parseInt(targetUserId)) {
            throw new Error('Cannot delete your own account');
        }
        
        // Check if current user has manage_users permission
        const hasPermission = await userHasPermission(currentUserId, 'manage_users');
        if (!hasPermission) {
            throw new Error('Insufficient permissions to delete users');
        }
        
        // Get target user info for logging
        const { data: targetUser, error: userError } = await supabase
            .from('users')
            .select('id, username, display_name, email')
            .eq('id', targetUserId)
            .single();
        
        if (userError || !targetUser) {
            throw new Error('Target user not found');
        }
        
        // Additional safety check - prevent deletion of other admin users unless deleter is also admin
        const currentUserRoles = await getUserRoles(currentUserId);
        const targetUserRoles = await getUserRoles(targetUserId);
        
        const isCurrentUserAdmin = currentUserRoles.some(role => role.name === 'admin');
        const isTargetUserAdmin = targetUserRoles.some(role => role.name === 'admin');
        
        // Only admins can delete other admins
        if (isTargetUserAdmin && !isCurrentUserAdmin) {
            throw new Error('Only administrators can delete admin accounts');
        }
        
        // Delete user (this will cascade delete user_roles due to foreign key constraint)
        const { error: deleteError } = await supabase
            .from('users')
            .delete()
            .eq('id', targetUserId);
        
        if (deleteError) {
            throw new Error(`User deletion failed: ${deleteError.message}`);
        }
        
        // Log the deletion (import this function in server.js if needed)
        try {
            const { logUserDeletion } = await import('./auditLogger.js');
            await logUserDeletion(currentUserId, targetUser);
        } catch (logError) {
            console.error('Logging error:', logError);
            // Don't fail the operation if logging fails
        }
        
        return {
            success: true,
            deletedUser: {
                id: targetUser.id,
                username: targetUser.username,
                display_name: targetUser.display_name
            }
        };
        
    } catch (error) {
        console.error('Error in deleteUserSecure:', error);
        throw error;
    }
}

// ================================
// Session Management Functions
// ================================

export const createUserSession = async (sessionId, userId, req) => {
    try {
        const userAgent = req.headers['user-agent'] || '';
        const ipAddress = req.ip || req.connection.remoteAddress || '';
        
        // Create fingerprint from user agent and IP
        const fingerprint = Buffer.from(`${userAgent}:${ipAddress}`).toString('base64');
        
        const { data, error } = await supabase
            .from('user_sessions')
            .insert({
                session_id: sessionId,
                user_id: userId,
                ip_address: ipAddress,
                user_agent: userAgent,
                fingerprint: fingerprint,
                created_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + 30 * 60 * 1000).toISOString(), // 30 minutes
                is_active: true
            })
            .select()
            .single();
        
        if (error) {
            throw new Error(`Session creation failed: ${error.message}`);
        }
        
        return data;
    } catch (error) {
        throw error;
    }
};

export const validateSession = async (sessionId) => {
    try {
        const { data: session, error } = await supabase
            .from('user_sessions')
            .select('*')
            .eq('session_id', sessionId)
            .eq('is_active', true)
            .gte('expires_at', new Date().toISOString())
            .single();
        
        if (error || !session) {
            return null;
        }
        
        // Update last_accessed timestamp
        await supabase
            .from('user_sessions')
            .update({ last_accessed: new Date().toISOString() })
            .eq('session_id', sessionId);
        
        return session;
    } catch (error) {
        return null;
    }
};

export const invalidateSession = async (sessionId) => {
    try {
        const { error } = await supabase
            .from('user_sessions')
            .update({ 
                is_active: false,
                invalidated_at: new Date().toISOString()
            })
            .eq('session_id', sessionId);
        
        if (error) {
            throw new Error(`Session invalidation failed: ${error.message}`);
        }
        
        return { success: true };
    } catch (error) {
        throw error;
    }
};

export const invalidateAllUserSessions = async (userId) => {
    try {
        const { error } = await supabase
            .from('user_sessions')
            .update({ 
                is_active: false,
                invalidated_at: new Date().toISOString()
            })
            .eq('user_id', userId)
            .eq('is_active', true);
        
        if (error) {
            throw new Error(`Session invalidation failed: ${error.message}`);
        }
        
        return { success: true };
    } catch (error) {
        throw error;
    }
};

export const cleanupExpiredSessions = async () => {
    try {
        const { error } = await supabase
            .from('user_sessions')
            .update({ is_active: false })
            .lt('expires_at', new Date().toISOString())
            .eq('is_active', true);
        
        if (error) {
            throw new Error(`Session cleanup failed: ${error.message}`);
        }
        
        return { success: true };
    } catch (error) {
        throw error;
    }
};

export const extendSession = async (sessionId, minutes = 30) => {
    try {
        const newExpiry = new Date(Date.now() + minutes * 60 * 1000).toISOString();
        
        const { error } = await supabase
            .from('user_sessions')
            .update({ 
                expires_at: newExpiry,
                last_accessed: new Date().toISOString()
            })
            .eq('session_id', sessionId)
            .eq('is_active', true);
        
        if (error) {
            throw new Error(`Session extension failed: ${error.message}`);
        }
        
        return { success: true, expires_at: newExpiry };
    } catch (error) {
        throw error;
    }
};