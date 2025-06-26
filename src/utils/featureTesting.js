// Create src/utils/testingHelpers.js for manual testing
export const testCases = {
    username: [
        { input: 'validuser123', expected: 'valid', description: 'Valid username' },
        { input: 'TestUser', expected: 'valid', description: 'Mixed case username' },
        { input: 'ab', expected: 'invalid', description: 'Too short' },
        { input: 'verylongusernamethatexceedslimit', expected: 'invalid', description: 'Too long' },
        { input: 'user@name', expected: 'invalid', description: 'Invalid characters' },
        { input: '_username', expected: 'invalid', description: 'Starting with special char' },
        { input: 'admin', expected: 'invalid', description: 'Reserved word' }
],

    email: [
        { input: 'user@example.com', expected: 'valid', description: 'Standard email' },
        { input: 'TestUser@EXAMPLE.COM', expected: 'valid', description: 'Mixed case email' },
        { input: 'userexample.com', expected: 'invalid', description: 'Missing @' },
        { input: 'test..user@example.com', expected: 'invalid', description: 'Consecutive dots' },
        { input: '', expected: 'invalid', description: 'Empty email' }
],

    password: [
        { input: 'SecurePassword123!', expected: 'valid', description: 'Strong password' },
        { input: 'Pass1', expected: 'invalid', description: 'Too short' },
        { input: 'password', expected: 'invalid', description: 'Common password' },
        { input: '123456789', expected: 'invalid', description: 'Sequential numbers' }
    ]
};

// Function to run validation tests
export const runValidationTests = () => {
    console.log('Running validation tests...');
  // Implementation for systematic testing
};