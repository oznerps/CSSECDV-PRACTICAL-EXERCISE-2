import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

// If you left both env‐vars blank, we export a stubbed client
export const supabase =
    supabaseUrl && supabaseAnonKey
        ? createClient(supabaseUrl, supabaseAnonKey)
        : {
            auth: {
                // no session by default
                session: () => null,
                // stub signIn, signUp, signOut to resolve immediately
                signIn: async () => ({ error: null }),
                signUp: async () => ({ user: null, error: null }),
                signOut: async () => ({ error: null }),
                // onAuthStateChange just invokes callback once
                onAuthStateChange: (_event, callback) => {
                    callback('SIGNED_OUT', null);
                    return { unsubscribe: () => { } };
                },
                api: {
                    // stub resetPasswordForEmail
                    resetPasswordForEmail: async () => ({ error: null }),
                },
            },
            // stub a minimal from(...).select(...) for the login lookup
            from: () => ({
                select: () => ({
                    single: async () => ({ data: { email: '' }, error: null }),
                }),
            }),
        };