const UserTemplate = ({user}) => {

    return(
        <div className="user-entry">
            <h3>{user.username}</h3>
            <p>{user.display_name}</p>
            <p>{user.email}</p>
            <p>{user.last_login}</p>
            
        </div>
    )

}
 export default UserTemplate