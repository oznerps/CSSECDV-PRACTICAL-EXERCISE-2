import React, { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import NavBar from './components/NavBar';
import ProtectedRoute from './components/ProtectedRoute';
import RequireAccess from './components/RequireAccess';
import SmartRedirect from './components/SmartRedirect';
import Login from './pages/Login';
import Register from './pages/Register';
import Home from './pages/Home';
import Dashboard from './pages/Dashboard';
import ForgotPassword from './pages/ForgotPassword';
import AdminDashboard from './pages/Admin';
import UserManagement from './pages/Users';
import Profile from './pages/Profile';
import Unauthorized from './pages/Unauthorized';
import { SessionTimeoutProvider, useSessionTimeout } from './contexts/SessionTimeoutContext';
import SessionWarningToast from './components/SessionWarningToast';
import SessionExpiredModal from './components/SessionExpiredModal';
import { registerSessionTimeoutHandler } from './utils/apiInterceptor';

// Inner App component that uses the session timeout context
function AppContent() {
    const { handleForceLogout } = useSessionTimeout();

    useEffect(() => {
        // Register the session timeout handler with the API interceptor
        registerSessionTimeoutHandler(handleForceLogout);
    }, [handleForceLogout]);

    return (
        <>
            <NavBar />
            <Routes>
                <Route path="/" element={<SmartRedirect />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                
                {/* Home page - first page after successful login */}
                <Route
                    path="/home"
                    element={
                        <ProtectedRoute>
                            <Home />
                        </ProtectedRoute>
                    }
                />

                {/* Dashboard - main application hub */}
                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    }
                />

                {/* Role-based protection - admin role only */}
                <Route
                    path="/admin"
                    element={
                        <RequireAccess requiredRole="admin">
                            <AdminDashboard />
                        </RequireAccess>
                    }
                />

                {/* Permission-based protection - user management */}
                <Route
                    path="/users"
                    element={
                        <RequireAccess requiredPermission="manage_users">
                            <UserManagement />
                        </RequireAccess>
                    }
                />

                {/* All authenticated users (as per PDF specification) */}
                <Route
                    path="/profile"
                    element={
                        <ProtectedRoute>
                            <Profile />
                        </ProtectedRoute>
                    }
                />

                <Route path="/unauthorized" element={<Unauthorized />} />   
            </Routes>
            
            {/* Session timeout notifications */}
            <SessionWarningToast />
            <SessionExpiredModal />
        </>
    );
}

// Main App component with SessionTimeoutProvider wrapper
export default function App() {
    return (
        <SessionTimeoutProvider>
            <AppContent />
        </SessionTimeoutProvider>
    );
}