import { useState, useEffect } from 'react';
import { Navigate } from 'react-router-dom';
import { getSession } from '../utils/sessionmanager';

const ProtectedRoute = ({ children, allowedRoles }) => {
  const [isAuthorized, setIsAuthorized] = useState(null);

  useEffect(() => {
    const user = getSession();

    if (!user) {
      setIsAuthorized(false);
      return;
    }

    const userRoles = Array.isArray(user.roles) ? user.roles : [user.role];

    if (!allowedRoles || allowedRoles.length === 0) {
      setIsAuthorized(true); // no restriction
    } else if (userRoles.some(role => allowedRoles.includes(role))) {
      setIsAuthorized(true); // at least one matching role
    } else {
      setIsAuthorized(false); // no matching role
    }
  }, [allowedRoles]);

  if (isAuthorized === null) {
    return <p style={{ textAlign: 'center', marginTop: '2rem' }}>Loading...</p>;
  }

  if (!isAuthorized) {
    const user = getSession();
    return user ? <Navigate to="/unauthorized" replace /> : <Navigate to="/login" replace />;
  }

  return children;
};

export default ProtectedRoute;