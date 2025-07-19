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

    if (!allowedRoles || allowedRoles.length === 0) {
      setIsAuthorized(true);
    } else if (allowedRoles.includes(user.role)) {
      setIsAuthorized(true);
    } else {
      setIsAuthorized(false);
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