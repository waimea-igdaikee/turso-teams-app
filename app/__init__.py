#===========================================================
# App Creation and Launch
#===========================================================

from flask import Flask, render_template, request, flash, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import html

from app.helpers.session import init_session
from app.helpers.db      import connect_db
from app.helpers.errors  import init_error, not_found_error
from app.helpers.logging import init_logging
from app.helpers.auth    import login_required
from app.helpers.time    import init_datetime, utc_timestamp, utc_timestamp_now


# Create the app
app = Flask(__name__)

# Configure app
init_session(app)   # Setup a session for messages, etc.
init_logging(app)   # Log requests
init_error(app)     # Handle errors and exceptions
init_datetime(app)  # Handle UTC dates in timestamps


#-----------------------------------------------------------
# Home page route
#-----------------------------------------------------------
@app.get("/")
def index():
    with connect_db() as client:
        # Get all the things from the DB
        sql = """
            SELECT code, name
            FROM teams
            ORDER BY name ASC
        """
        params=[]
        result = client.execute(sql, params)
        teams = result.rows

        # And show them on the page
        return render_template("pages/home.jinja", teams=teams)


#-----------------------------------------------------------
# About page route
#-----------------------------------------------------------
@app.get("/about/")
def about():
    return render_template("pages/about.jinja")


#-----------------------------------------------------------
# Things page route - Show all the things, and new thing form
#-----------------------------------------------------------
@app.get("/things/")
def show_all_things():
    with connect_db() as client:
        # Get all the things from the DB
        sql = """
            SELECT things.id,
                   things.name,
                   users.name AS owner

            FROM things
            JOIN users ON things.user_id = users.id

            ORDER BY things.name ASC
        """
        params=[]
        result = client.execute(sql, params)
        things = result.rows

        # And show them on the page
        return render_template("pages/things.jinja", things=things)


#-----------------------------------------------------------
# Thing page route - Show details of a single thing
#-----------------------------------------------------------
@app.get("/team/<code>")
def show_one_team(code):
    with connect_db() as client:
        # Get the team details from the DB, including the owner info
        sql1= """
            SELECT teams.code,
                   teams.name,
                   teams.description,
                   teams.manager

            FROM teams
            JOIN users ON teams.manager = users.id

            WHERE teams.code=?
        """
        params = [code]
        result1 = client.execute(sql1, params)

        sql2= "SELECT * FROM players"
        result2 = client.execute(sql2)

        # Did we get a result?
        if result.rows:
            # yes, so show it on the page
            team = result1.rows[0]
            players = result2
            return render_template("pages/team.jinja", team=team, players=players)

        else:
            # No, so show error
            return not_found_error()


#-----------------------------------------------------------
# Route for adding a team, using data posted from a form
# - Restricted to logged in users
#-----------------------------------------------------------
@app.post("/add")
@login_required
def add_a_thing():
    # Get the data from the form
    code  = request.form.get("code")
    name = request.form.get("name")
    description = request.form.get("description")

    # Sanitise the text inputs
    name = html.escape(name)

    # Get the user id from the session
    user_id = session["user_id"]

    with connect_db() as client:
        # Add the thing to the DB
        sql = "INSERT INTO teams (code, name, description, manager) VALUES (?, ?, ?, ?)"
        params = [code, name, description, session["user_id"]]
        client.execute(sql, params)

        # Go back to the home page
        flash(f"Team '{name}' added", "success")
        return redirect("/")


#-----------------------------------------------------------
# Route for deleting a thing, Id given in the route
# - Restricted to logged in users
#-----------------------------------------------------------
@app.get("/delete/<int:id>")
@login_required
def delete_a_thing(id):
    # Get the user id from the session
    user_id = session["user_id"]

    with connect_db() as client:
        # Delete the thing from the DB only if we own it
        sql = "DELETE FROM things WHERE id=? AND user_id=?"
        params = [id, user_id]
        client.execute(sql, params)

        # Go back to the home page
        flash("Thing deleted", "success")
        return redirect("/things")







#-----------------------------------------------------------
# User registration form route
#-----------------------------------------------------------
@app.get("/register")
def register_form():
    return render_template("pages/register.jinja")


#-----------------------------------------------------------
# User login form route
#-----------------------------------------------------------
@app.get("/login")
def login_form():
    return render_template("pages/login.jinja")


#-----------------------------------------------------------
# Route for adding a user when registration form submitted
#-----------------------------------------------------------
@app.post("/add-user")
def add_user():
    # Get the data from the form
    name = request.form.get("name")
    username = request.form.get("username")
    password = request.form.get("password")

    with connect_db() as client:
        # Attempt to find an existing record for that user
        sql = "SELECT * FROM users WHERE username = ?"
        params = [username]
        result = client.execute(sql, params)

        # No existing record found, so safe to add the user
        if not result.rows:
            # Sanitise the name
            name = html.escape(name)

            # Salt and hash the password
            hash = generate_password_hash(password)

            # Add the user to the users table
            sql = "INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)"
            params = [name, username, hash]
            client.execute(sql, params)

            # And let them know it was successful and they can login
            flash("Registration successful", "success")
            return redirect("/login")

        # Found an existing record, so prompt to try again
        flash("Username already exists. Try again...", "error")
        return redirect("/register")


#-----------------------------------------------------------
# Route for processing a user login
#-----------------------------------------------------------
@app.post("/login-user")
def login_user():
    # Get the login form data
    username = request.form.get("username")
    password = request.form.get("password")

    with connect_db() as client:
        # Attempt to find a record for that user
        sql = "SELECT * FROM users WHERE username = ?"
        params = [username]
        result = client.execute(sql, params)

        # Did we find a record?
        if result.rows:
            # Yes, so check password
            user = result.rows[0]
            hash = user["password_hash"]

            # Hash matches?
            if check_password_hash(hash, password):
                # Yes, so save info in the session
                session["user_id"]   = user["id"]
                session["user_name"] = user["name"]
                session["logged_in"] = True

                # And head back to the home page
                flash("Login successful", "success")
                return redirect("/")

        # Either username not found, or password was wrong
        flash("Invalid credentials", "error")
        return redirect("/login")


#-----------------------------------------------------------
# Route for processing a user logout
#-----------------------------------------------------------
@app.get("/logout")
def logout():
    # Clear the details from the session
    session.pop("user_id", None)
    session.pop("user_name", None)
    session.pop("logged_in", None)

    # And head back to the home page
    flash("Logged out successfully", "success")
    return redirect("/")

