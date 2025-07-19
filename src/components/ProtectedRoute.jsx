import { Navigate } from 'react-router-dom';
import { getSession } from '../utils/sessionmanager';

const ProtectedRoute = ({ children, fallbackPath = '/unauthorized' }) => {
    const user = getSession();
    
    // Simple authentication check - server handles authorization
    if (!user) {
        return <Navigate to="/login" replace />;
    }

    return children;
};

export default ProtectedRoute;