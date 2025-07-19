import { Navigate } from 'react-router-dom';
import PropTypes from 'prop-types';
import { getSession } from '../utils/SessionManager';

const ProtectedRoute = ({ children, fallbackPath = '/unauthorized' }) => {
    const user = getSession();
    
    // Simple authentication check - server handles authorization
    if (!user) {
        return <Navigate to="/login" replace />;
    }

    return children;
};

// PropTypes validation
ProtectedRoute.propTypes = {
    children: PropTypes.node.isRequired,
    fallbackPath: PropTypes.string
};

// Default props
ProtectedRoute.defaultProps = {
    fallbackPath: '/unauthorized'
};

export default ProtectedRoute;