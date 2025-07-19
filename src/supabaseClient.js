import { createClient } from '@supabase/supabase-js';

// Environment variable detection for both browser and Node.js
let supabaseUrl, supabaseAnonKey;

if (typeof window !== 'undefined') {
    // Browser environment
    supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
    supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;
} else {
    // Node.js environment
    try {
        await import('dotenv/config');
    } catch (error) {
        // dotenv not available, continue
    }
    
    supabaseUrl = process.env.VITE_SUPABASE_URL;
    supabaseAnonKey = process.env.VITE_SUPABASE_ANON_KEY;
}

if (!supabaseUrl || !supabaseAnonKey) {
    console.error('Supabase configuration missing');
    console.error('VITE_SUPABASE_URL:', supabaseUrl ? 'Found' : 'Missing');
    console.error('VITE_SUPABASE_ANON_KEY:', supabaseAnonKey ? 'Found' : 'Missing');
    throw new Error('Supabase configuration incomplete');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
    auth: {
        autoRefreshToken: typeof window !== 'undefined',
        persistSession: typeof window !== 'undefined'
    }
});

console.log('Supabase client initialized successfully');