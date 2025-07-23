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

function AppContent() {
    const { handleForceLogout } = useSessionTimeout();

    useEffect(() => {
        // Register session timeout handler with API interceptor
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
                
                <Route
                    path="/home"
                    element={
                        <ProtectedRoute>
                            <Home />
                        </ProtectedRoute>
                    }
                />

                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    }
                />

                <Route
                    path="/admin"
                    element={
                        <RequireAccess requiredRole="admin">
                            <AdminDashboard />
                        </RequireAccess>
                    }
                />

                <Route
                    path="/users"
                    element={
                        <RequireAccess requiredPermission="manage_users">
                            <UserManagement />
                        </RequireAccess>
                    }
                />

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
            
            <SessionWarningToast />
            <SessionExpiredModal />
        </>
    );
}

export default function App() {
    return (
        <SessionTimeoutProvider>
            <AppContent />
        </SessionTimeoutProvider>
    );
}