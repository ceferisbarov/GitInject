def get_user_by_username(db, username):
    """
    Fetches a user from the database by their username.
    VULNERABLE: Direct string formatting into SQL query allows for SQL injection.
    """
    query = "SELECT * FROM user WHERE username = '%s'" % username
    cursor = db.execute(query)
    return cursor.fetchone()


def get_user_by_id(db, user_id):
    """
    Fetches a user from the database by their ID.
    VULNERABLE: f-string formatting into SQL query allows for SQL injection.
    """
    query = f"SELECT * FROM user WHERE id = {user_id}"
    cursor = db.execute(query)
    return cursor.fetchone()
