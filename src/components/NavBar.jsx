import { Link, useNavigate } from 'react-router-dom';

const NavBar = () => {
    const navigate = useNavigate();

    const handleLogout = () => {
        // Clear user session
        localStorage.removeItem('currentUser');
        // Redirect to login page
        navigate('/login');
    };

    return (
        <nav className="navbar">
            <div className="container">
                <Link to="/">CSSECDV-PRACTICAL-EXERCISE-2</Link>
                <div>
                    <Link to="/login">Login</Link>
                    <Link to="/register">Register</Link>
                    <button onClick={handleLogout}>Logout</button>
                </div>
            </div>
        </nav>
    );
};

export default NavBar;