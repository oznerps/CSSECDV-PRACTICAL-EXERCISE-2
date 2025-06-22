import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase =
    supabaseUrl && supabaseAnonKey
        ? createClient(supabaseUrl, supabaseAnonKey)
        : {
            auth: {
                session: () => null,
                signIn: async () => ({ error: null }),
                signUp: async () => ({ user: null, error: null }),
                signOut: async () => ({ error: null }),
                // *** FIXED stub: accept a single callback argument ***
                onAuthStateChange: (callback) => {
                    // immediately invoke once with signed-out
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