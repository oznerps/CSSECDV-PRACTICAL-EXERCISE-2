import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import NavBar from './components/NavBar';
import ProtectedRoute from './components/ProtectedRoute';
import RequirePermission from './components/RequirePermission';
import RequireRole from './components/requireRole';
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

                {/* Role-based protection - admin role only */}
                <Route
                    path="/admin"
                    element={
                        <RequireRole requiredRole="admin">
                            <AdminDashboard />
                        </RequireRole>
                    }
                />

                {/* Role-based protection - admin and manager roles */}
                <Route
                    path="/users"
                    element={
                        <RequirePermission requiredPermission="manage_users">
                            <UserManagement />
                        </RequirePermission>
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
        </>
    );
}