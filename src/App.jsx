import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import NavBar from './components/NavBar';
import ProtectedRoute from './components/ProtectedRoute';
import RequirePermission from './components/RequirePermission';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import ForgotPassword from './pages/ForgotPassword';
import AdminDashboard from './pages/Admin';
import UserManagement from './pages/Users';
import Profile from './pages/Profile';
import Unauthorized from './pages/Unauthorized';

export default function App() {
    return (
        <>
            <NavBar />
            <Routes>
                <Route path="/" element={<Navigate to="/login" replace />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                
                {/* Basic authentication - any logged-in user */}
                <Route
                    path="/dashboard"
                    element={
                        <ProtectedRoute>
                            <Dashboard />
                        </ProtectedRoute>
                    }
                />

                {/* Permission-based protection - requires specific administrative permission */}
                <Route
                    path="/admin-dashboard"
                    element={
                        <RequirePermission requiredPermission="admin_access">
                            <AdminDashboard />
                        </RequirePermission>
                    }
                />

                {/* Permission-based protection - requires user management permission */}
                <Route
                    path="/user-management"
                    element={
                        <RequirePermission requiredPermission="manage_users">
                            <UserManagement />
                        </RequirePermission>
                    }
                />

                {/* Permission-based profile access */}
                <Route
                    path="/profile"
                    element={
                        <RequirePermission requiredPermission="edit_profile">
                            <Profile />
                        </RequirePermission>
                    }
                />

                <Route path="/unauthorized" element={<Unauthorized />} />   
            </Routes>
        </>
    );
}