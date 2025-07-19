import { useState, useEffect } from 'react';
import { getAllRoles, updateUserRoles, userHasPermission } from '../utils/databaseAPI.js';
import { getSession } from '../utils/sessionmanager.js';

const UserTemplate = ({ user, onUserUpdate }) => {
    // State for role editing functionality
    const [isEditing, setIsEditing] = useState(false);
    const [availableRoles, setAvailableRoles] = useState([]);
    const [selectedRoles, setSelectedRoles] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [canManageUsers, setCanManageUsers] = useState(false);
    const [error, setError] = useState(null);

    // Check if current user has permission to manage other users
    useEffect(() => {
        const checkManagePermissions = async () => {
            try {
                const currentUser = getSession();
                if (currentUser && currentUser.id) {
                    // Use your permission checking function
                    const hasPermission = await userHasPermission(currentUser.id, 'manage_users');
                    setCanManageUsers(hasPermission);
                    console.log('User can manage roles:', hasPermission);
                }
            } catch (error) {
                console.error('Error checking manage permissions:', error);
                setCanManageUsers(false);
            }
        };

        checkManagePermissions();
    }, []);

    // Initialize selected roles when user prop changes
    useEffect(() => {
        if (user && user.roles) {
            // Extract role IDs from the user's current roles
            const currentRoleIds = user.roles.map(role => role.id);
            setSelectedRoles(currentRoleIds);
        }
    }, [user]);

    // Start editing: load all available roles from the system
    const handleStartEdit = async () => {
        try {
            setError(null);
            setIsLoading(true);
            
            // Fetch all available roles using RBAC function
            const roles = await getAllRoles();
            setAvailableRoles(roles);
            setIsEditing(true);
            
            console.log('Available roles loaded for editing:', roles);
        } catch (error) {
            console.error('Error loading available roles:', error);
            setError('Failed to load available roles');
        } finally {
            setIsLoading(false);
        }
    };

    // Save role changes: update the user's roles in the database
    const handleSaveRoles = async () => {
        try {
            setError(null);
            setIsLoading(true);
            
            console.log('Saving roles for user:', user.id, 'New roles:', selectedRoles);
            
            // This function handles removing old roles and adding new ones
            await updateUserRoles(user.id, selectedRoles);
            
            setIsEditing(false);
            
            // Refresh the parent component's user list to show updated roles
            if (onUserUpdate) {
                await onUserUpdate();
            }
            
            console.log('Roles updated successfully');
        } catch (error) {
            console.error('Error updating user roles:', error);
            setError('Failed to update user roles. Please try again.');
        } finally {
            setIsLoading(false);
        }
    };

    // Cancel editing: reset to original state
    const handleCancelEdit = () => {
        // Reset selected roles to user's current roles
        if (user && user.roles) {
            const currentRoleIds = user.roles.map(role => role.id);
            setSelectedRoles(currentRoleIds);
        }
        setIsEditing(false);
        setError(null);
    };

    // Handle checkbox changes for role selection
    const handleRoleToggle = (roleId, isChecked) => {
        if (isChecked) {
            // Add role if not already selected
            if (!selectedRoles.includes(roleId)) {
                setSelectedRoles([...selectedRoles, roleId]);
            }
        } else {
            // Remove role from selection
            setSelectedRoles(selectedRoles.filter(id => id !== roleId));
        }
    };

    // Format the last login date for display
    const formatLastLogin = (lastLogin) => {
        if (!lastLogin) return 'Never';
        return new Date(lastLogin).toLocaleDateString();
    };

    // Display current roles as a readable string
    const displayCurrentRoles = () => {
        if (!user.roles || user.roles.length === 0) {
            return 'No roles assigned';
        }
        return user.roles.map(role => role.name).join(', ');
    };

    return (
        <div className="user-entry">
            {/* Basic user information - unchanged from your original */}
            <div className="user-info">
                <h4>{user.username}</h4>
            </div>
            
            <div className="user-info">
                <p>{user.display_name}</p>
            </div>
            
            <div className="user-info">
                <p>{user.email}</p>
            </div>
            
            <div className="user-info">
                <p>{formatLastLogin(user.last_login)}</p>
            </div>
            
            {/*Role management section */}
            <div className="user-roles">
                {error && (
                    <div className="role-error" style={{color: 'red', fontSize: '0.9rem', marginBottom: '0.5rem'}}>
                        {error}
                    </div>
                )}
                
                {!isEditing ? (
                    // Display mode: show current roles and edit button if permitted
                    <div className="roles-display">
                        <p className="current-roles">{displayCurrentRoles()}</p>
                        
                        {canManageUsers && (
                            <button 
                                className="edit-roles-btn"
                                onClick={handleStartEdit}
                                disabled={isLoading}
                            >
                                {isLoading ? 'Loading...' : 'Edit Roles'}
                            </button>
                        )}
                    </div>
                ) : (
                    // Edit mode: show checkboxes for all available roles
                    <div className="roles-edit">
                        <p style={{fontSize: '0.9rem', fontWeight: 'bold', marginBottom: '0.5rem'}}>
                            Select roles for {user.display_name}:
                        </p>
                        
                        <div className="role-checkboxes">
                            {availableRoles.map(role => (
                                <label key={role.id} className="role-checkbox-label">
                                    <input
                                        type="checkbox"
                                        checked={selectedRoles.includes(role.id)}
                                        onChange={(e) => handleRoleToggle(role.id, e.target.checked)}
                                        disabled={isLoading}
                                    />
                                    <span className="role-info">
                                        <strong>{role.name}</strong>
                                        {role.description && (
                                            <span className="role-description"> - {role.description}</span>
                                        )}
                                    </span>
                                </label>
                            ))}
                        </div>
                        
                        <div className="role-edit-buttons">
                            <button 
                                className="save-roles-btn"
                                onClick={handleSaveRoles} 
                                disabled={isLoading}
                            >
                                {isLoading ? 'Saving...' : 'Save Changes'}
                            </button>
                            
                            <button 
                                className="cancel-roles-btn"
                                onClick={handleCancelEdit}
                                disabled={isLoading}
                            >
                                Cancel
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default UserTemplate;