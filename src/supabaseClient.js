import { createClient } from '@supabase/supabase-js';

// Handle both Vite (frontend) and Node.js (backend) environments
const supabaseUrl = typeof import.meta !== 'undefined' && import.meta.env 
    ? import.meta.env.VITE_SUPABASE_URL 
    : process.env.VITE_SUPABASE_URL;

const supabaseAnonKey = typeof import.meta !== 'undefined' && import.meta.env
    ? import.meta.env.VITE_SUPABASE_ANON_KEY
    : process.env.VITE_SUPABASE_ANON_KEY;

export const supabase =
    supabaseUrl && supabaseAnonKey
        ? createClient(supabaseUrl, supabaseAnonKey)
        : {
            auth: {
                session: () => null,
                signIn: async () => ({ error: null }),
                signUp: async () => ({ user: null, error: null }),
                signOut: async () => ({ error: null }),
                onAuthStateChange: (callback) => {
                    callback('SIGNED_OUT', null);
                    return { unsubscribe: () => { } };
                },
                api: {
                    resetPasswordForEmail: async () => ({ error: null }),
                },
            },
            from: () => ({
                select: () => ({
                    single: async () => ({ data: { email: '' }, error: null }),
                }),
            }),
        };