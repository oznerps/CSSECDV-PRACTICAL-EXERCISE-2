import bcrypt from 'bcryptjs';

// Configure bcrypt with cost factor 12 (as required by exercise)
const SALT_ROUNDS = 12;

export const hashPassword = async (password) => {
    try {
        // Generate salt and hash password
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    } catch (error) {
    throw new Error('Failed to hash password');
    }
};

export const verifyPassword = async (password, hashedPassword) => {
    try {
        return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
    throw new Error('Failed to verify password');
    }
};