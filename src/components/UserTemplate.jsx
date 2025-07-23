import { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { getAllRoles, updateUserRoles, userHasPermission, deleteUserSecure } from '../utils/databaseAPI.js';
import { getSession } from '../utils/SessionManager.js';

const UserTemplate = ({ user, onUserUpdate }) => {
    // State for role editing functionality
    const [isEditing, setIsEditing] = useState(false);
    const [availableRoles, setAvailableRoles] = useState([]);
    const [selectedRoles, setSelectedRoles] = useState([]);
    const [isLoading, setIsLoading] = useState(false);
    const [canManageUsers, setCanManageUsers] = useState(false);
    const [error, setError] = useState(null);
    const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
    const [isDeleting, setIsDeleting] = useState(false);

    // Check if current user has permission to manage other users
    useEffect(() => {
        const checkManagePermissions = async () => {
            try {
                const currentUser = getSession();
                if (currentUser && currentUser.id) {
                    // Use permission checking function
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

    // Handle delete user confirmation
    const handleDeleteUser = async () => {
        try {
            setError(null);
            setIsDeleting(true);
            
            const currentUser = getSession();
            if (!currentUser) {
                throw new Error('No current user session');
            }
            
            console.log('Deleting user:', user.id, 'by:', currentUser.id);
            
            // Call the secure delete function
            const result = await deleteUserSecure(currentUser.id, user.id);
            
            setShowDeleteConfirm(false);
            
            // Refresh the parent component's user list
            if (onUserUpdate) {
                await onUserUpdate();
            }
            
            console.log('User deleted successfully:', result.deletedUser);
        } catch (error) {
            console.error('Error deleting user:', error);
            setError(`Failed to delete user: ${error.message}`);
            setShowDeleteConfirm(false);
        } finally {
            setIsDeleting(false);
        }
    };

    // Show delete confirmation dialog
    const handleShowDeleteConfirm = () => {
        setError(null);
        setShowDeleteConfirm(true);
    };

    // Cancel delete operation
    const handleCancelDelete = () => {
        setShowDeleteConfirm(false);
        setError(null);
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
            {/* Basic user information*/}
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
                            <div className="user-actions">
                                <button 
                                    className="edit-roles-btn"
                                    onClick={handleStartEdit}
                                    disabled={isLoading || isDeleting}
                                >
                                    {isLoading ? 'Loading...' : 'Edit Roles'}
                                </button>
                                
                                <button 
                                    className="delete-user-btn"
                                    onClick={handleShowDeleteConfirm}
                                    disabled={isLoading || isDeleting}
                                    style={{
                                        backgroundColor: '#dc3545',
                                        color: 'white',
                                        marginLeft: '0.5rem'
                                    }}
                                >
                                    {isDeleting ? 'Deleting...' : 'Delete User'}
                                </button>
                            </div>
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
            
            {/* Delete confirmation dialog */}
            {showDeleteConfirm && (
                <div className="delete-confirmation" style={{
                    position: 'fixed',
                    top: '50%',
                    left: '50%',
                    transform: 'translate(-50%, -50%)',
                    backgroundColor: 'white',
                    padding: '2rem',
                    border: '1px solid #ccc',
                    borderRadius: '8px',
                    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
                    zIndex: 1000,
                    minWidth: '300px'
                }}>
                    <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>
                        ⚠️ Confirm User Deletion
                    </h3>
                    <p style={{ marginBottom: '1.5rem' }}>
                        Are you sure you want to delete user <strong>{user.display_name}</strong> (@{user.username})?
                    </p>
                    <p style={{ 
                        fontSize: '0.9rem', 
                        color: '#666', 
                        marginBottom: '1.5rem',
                        fontStyle: 'italic'
                    }}>
                        This action cannot be undone. All user data and sessions will be permanently removed.
                    </p>
                    
                    <div className="confirmation-buttons" style={{ 
                        display: 'flex', 
                        gap: '1rem',
                        justifyContent: 'flex-end'
                    }}>
                        <button 
                            onClick={handleCancelDelete}
                            disabled={isDeleting}
                            style={{
                                padding: '0.5rem 1rem',
                                backgroundColor: '#6c757d',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            Cancel
                        </button>
                        
                        <button 
                            onClick={handleDeleteUser}
                            disabled={isDeleting}
                            style={{
                                padding: '0.5rem 1rem',
                                backgroundColor: '#dc3545',
                                color: 'white',
                                border: 'none',
                                borderRadius: '4px',
                                cursor: 'pointer'
                            }}
                        >
                            {isDeleting ? 'Deleting...' : 'Delete User'}
                        </button>
                    </div>
                </div>
            )}
            
            {/* Backdrop for delete confirmation */}
            {showDeleteConfirm && (
                <div 
                    className="modal-backdrop"
                    style={{
                        position: 'fixed',
                        top: 0,
                        left: 0,
                        right: 0,
                        bottom: 0,
                        backgroundColor: 'rgba(0, 0, 0, 0.5)',
                        zIndex: 999
                    }}
                    onClick={handleCancelDelete}
                />
            )}
        </div>
    );
};

// PropTypes validation
UserTemplate.propTypes = {
    user: PropTypes.shape({
        id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
        username: PropTypes.string.isRequired,
        display_name: PropTypes.string.isRequired,
        email: PropTypes.string.isRequired,
        last_login: PropTypes.string,
        roles: PropTypes.arrayOf(PropTypes.shape({
            id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
            name: PropTypes.string.isRequired,
            description: PropTypes.string
        }))
    }).isRequired,
    onUserUpdate: PropTypes.func
};

// Default props
UserTemplate.defaultProps = {
    onUserUpdate: null
};

export default UserTemplate;