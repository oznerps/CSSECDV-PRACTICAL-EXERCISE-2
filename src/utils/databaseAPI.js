import { supabase } from '../supabaseClient';
import { hashPassword, verifyPassword } from './passwordUtils';
import { validateUsername, validateEmail, validatePassword, sanitizeInput } from './validation';

// Function to register a new user
export const registerUser = async (userData) => {
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

  // Hash the password
    const passwordHash = await hashPassword(password);

  // Insert new user
    const { data, error } = await supabase
        .from('users')
        .insert([
{
        username: sanitizedUsername.toLowerCase(),
        display_name: sanitizedDisplayName,
        email: emailValidation.normalizedEmail,
        password_hash: passwordHash,
        hash_algorithm: 'bcrypt'
}
    ])
    .select()
    .single();

    if (error) {
    // Handle database constraint errors
        if (error.code === '23505') { // Unique constraint violation
            if (error.detail.includes('username')) {
                throw new Error('Username already exists');
                }else if (error.detail.includes('email')) {
                throw new Error('An account with this email already exists');
}
    }
    throw new Error('Registration failed. Please try again.');
    }

    return data;
};

// Function to authenticate a user (login)
export const authenticateUser = async (identifier, password) => {
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

  // Update last login timestamp
    await supabase
        .from('users')
        .update({ last_login: new Date().toISOString() })
        .eq('id', user.id);

  // Return user data (without password hash)
    const { password_hash, ...userWithoutPassword } = user;
    return userWithoutPassword;
};