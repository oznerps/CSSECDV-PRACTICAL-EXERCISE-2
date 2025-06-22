import { useState, useEffect } from 'react';
import { supabase } from '../supabaseClient';
import { Navigate } from 'react-router-dom';

const ProtectedRoute = ({ children }) => {
    const [session, setSession] = useState(null);
    useEffect(() => {
        const s = supabase.auth.session();
        setSession(s);
        const { data: listener } = supabase.auth.onAuthStateChange((_event, s) => {
            setSession(s);
        });
        return () => { listener?.unsubscribe(); };
    }, []);
    if (!session) return <Navigate to="/login" replace />;
    return children;
};

export default ProtectedRoute;