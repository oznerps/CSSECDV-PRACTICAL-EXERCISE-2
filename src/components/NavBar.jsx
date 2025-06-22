import { Link } from 'react-router-dom';
import { supabase } from '../supabaseClient';

const NavBar = () => {
    const handleLogout = async () => {
        await supabase.auth.signOut();
        window.location.href = '/login';
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