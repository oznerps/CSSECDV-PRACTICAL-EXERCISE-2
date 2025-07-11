import { supabase } from '../supabaseClient';
import { hashPassword, verifyPassword } from './passwordUtils';
import { validateUsername, validateEmail, validatePassword, sanitizeInput } from './Validation';

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

        // Hash password
        const saltRounds = 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Insert user
        const { data: newUser, error: insertError } = await supabase
            .from('users')
            .insert({
                username: sanitizedUsername.toLowerCase(), // Fixed: use sanitized version
                display_name: sanitizedDisplayName, // Fixed: use sanitized version
                email: emailValidation.normalizedEmail, // Fixed: use normalized email
                password_hash: passwordHash,
                hash_algorithm: 'bcrypt'
            })
            .select()
            .single();
        
        if (insertError) {
            throw new Error(`Registration failed: ${insertError.message}`);
        }
        
        // ===== NEW: Assign default 'user' role =====
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

        // ===== NEW: Get user roles and permissions =====
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