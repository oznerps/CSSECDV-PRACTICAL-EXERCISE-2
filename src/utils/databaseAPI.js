import { supabase } from '../supabaseClient';
import { hashPassword, verifyPassword } from './passwordUtils';
import { validateUsername, validateEmail, validatePassword, sanitizeInput } from './validation';

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

        // Check for existing username (case-insensitive)
        const { data: existingUsername } = await supabase
            .from('users')
            .select('id')
            .ilike('username', sanitizedUsername.toLowerCase())
            .single();
        
        if (existingUsername) {
            throw new Error('Username already exists');
        }

        // Check for existing email (case-insensitive)
        const { data: existingEmail } = await supabase
            .from('users')
            .select('id')
            .ilike('email', emailValidation.normalizedEmail)
            .single();
        
        if (existingEmail) {
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
        const defaultRole = await getRoleByName('user');
        await assignUserRole(newUser.id, defaultRole.id);
        
        return newUser;
        
    } catch (error) {
        throw error;
    }
};

// Function to authenticate a user (login) - Updated with RBAC
export const authenticateUser = async (identifier, password) => {
    try {
        // Sanitize input
        const sanitizedIdentifier = sanitizeInput(identifier);

        if (!sanitizedIdentifier || !password) {
            throw new Error('Invalid username/email or password');
        }

        // Determine if identifier is email or username
        const isEmail = sanitizedIdentifier.includes('@');

        let query = supabase.from('users').select('*');

        if (isEmail) {
            // Search by email (case-insensitive)
            query = query.ilike('email', sanitizedIdentifier.toLowerCase());
        } else {
            // Search by username (case-insensitive)
            query = query.ilike('username', sanitizedIdentifier.toLowerCase());
        }

        const { data: user, error } = await query.single();

        // Generic error message to prevent user enumeration
        if (error || !user) {
            throw new Error('Invalid username/email or password');
        }

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
        throw new Error(`Failed to fetch user roles: ${error.message}`);
    }
    
    return data.map(item => item.roles);
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
        throw new Error(`Failed to fetch user permissions: ${error.message}`);
    }
    
    // Flatten the nested structure to get permission names
    const permissions = new Set();
    data.forEach(userRole => {
        userRole.roles.role_permissions.forEach(rolePermission => {
            permissions.add(rolePermission.permissions.name);
        });
    });
    
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
        roles: user.user_roles.map(ur => ur.roles)
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
    
    return data;
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
        const { logRoleChange } = await import('./auditLogger.js');
        await logRoleChange(currentUserId, targetUserId, oldRoles, newRoles);
        
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
        
        const roles = user.user_roles.map(ur => ur.roles);
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
 * Enhanced role assignment with validation
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
