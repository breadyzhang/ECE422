import pymysql as mdb
from bottle import FormsDict
from hashlib import sha256
import os

# connection to database project2
def connect():
    """makes a connection to MySQL database.
    @return a mysqldb connection
    """

    #TODO: 1 of 6 fill out MySQL connection parameters. 
    # Use the netid and given password of the repo you are committing your solution to.
    # See the file we gave you called dbrw.secret in your repo.
    # Do not change this value - we use it when grading. 

    return mdb.connect(host="localhost",
                       user="fz8",
                       passwd="26481a6b400c704aa95d577f72222c09b5f7e9ad661cde2618334224129f2bb9",
                       db="project2");

def createUser(username, password):
    """ creates a row in table named users
    @param username: username of user
    @param password: password of user
    """

    salt = os.urandom(32)
    salted = salt + str.encode(password)

    m = sha256()
    m.update(salted)
    passwordhash = hex(int.from_bytes(m.digest(), byteorder="big"))[2:]
    salt = hex(int.from_bytes(salt, byteorder="big"))[2:]

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO 2 of 6. Use cur.execute() to insert a new row into the users table containing the username, salt, and passwordhash
    cur.execute("insert into users (username, salt, passwordhash) values (%s, %s, %s);", (username, salt, passwordhash))
    db_rw.commit()

def validateUser(username, password):
    """ validates if username,password pair provided by user is correct or not
    @param username: username of user
    @param password: password of user
    @return True if validation was successful, False otherwise.
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO 3 of 6. Use cur.execute() to select the appropriate user record (if it exists)
    cur.execute("select salt,passwordhash from users where username = %s", (username))
    if cur.rowcount < 1:
        return False

    user_record = cur.fetchone()
    salt_hex = user_record[0]
    while len(salt_hex) < 64:
        salt_hex = "0" + salt_hex
    salt = bytes.fromhex(user_record[0])
    passwordhash_authoritative = user_record[1]
    salted = salt + str.encode(password)

    m = sha256()
    m.update(salted)
    passwordhash = hex(int.from_bytes(m.digest(), byteorder="big"))[2:]

    if passwordhash_authoritative == passwordhash:
        return True
    else:
        return False

def fetchUser(username):
    """ checks if there exists given username in table users or not
    if user exists return (id, username) pair
    if user does not exist return None
    @param username: the username of a user
    @return The row which has username is equal to provided input
    """

    db_rw = connect()
    cur = db_rw.cursor(mdb.cursors.DictCursor)
    #TODO 4 of 6. Use cur.execute() to fetch the row with this username from the users table, if it exists
    cur.execute("select * from users where username = %s", (username))
    if cur.rowcount < 1:
        return None    
    return FormsDict(cur.fetchone())

def addHistory(user_id, query):
    """ adds a query from user with id=user_id into table named history
    @param user_id: integer id of user
    @param query: the query user has given as input
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO 5 of 6. Use cur.execute() to add a row to the history table containing the correct user_id and query 
    cur.execute('INSERT INTO history (user_id, query) values(%s, %s);', (user_id, query))
    db_rw.commit()
    
def getHistory(user_id):
    """ grabs last 15 queries made by user with id=user_id from
    table named history in descending order of when the searches were made
    @param user_id: integer id of user
    @return a first column of a row which MUST be query
    """

    db_rw = connect()
    cur = db_rw.cursor()
    #TODO 6 of 6. Use cur.execute() to fetch the most recent 15 queries from this user (including duplicates). 
    # Note: Make sure the query text is at index 0 in the returned rows. 
    # Otherwise you will get an error when the templating engine tries to use this object to build the HTML reply.
    cur.execute('select query,id,user_id from history where user_id = %s order by id desc limit 15', (user_id))
    rows = cur.fetchall();
    return [row[0] for row in rows]
