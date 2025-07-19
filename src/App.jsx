import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import NavBar from './components/NavBar';
import ProtectedRoute from './components/ProtectedRoute';
import RequirePermission from './components/RequirePermission'; // New import
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import ForgotPassword from './pages/ForgotPassword';
import AdminDashboard from './pages/AdminDashboard';
import UserManagement from './pages/UserManagement';
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

                {/* Layered security - requires BOTH role AND permission */}
                <Route
                    path="/user-management"
                    element={
                        <ProtectedRoute 
                            allowedRoles={['admin', 'manager']}
                            requiredPermissions={['manage_users']}
                        >
                            <UserManagement />
                        </ProtectedRoute>
                    }
                />

                {/* Permission-based profile access - more flexible than role-based */}
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