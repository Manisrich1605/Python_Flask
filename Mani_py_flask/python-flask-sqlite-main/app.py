from flask import Flask, render_template, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask import request, jsonify
import sqlite3


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
bcrypt = Bcrypt(app)


#login and register----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
   def __init__(self, user_id, username, password, role='user'):  # Adding a role attribute
       self.id = user_id
       self.username = username
       self.password = password
       self.role = role  # Assign a role to the user

@login_manager.user_loader
def load_user(user_id):
   # Implement your logic to load a user from the database based on user_id
   conn = sqlite3.connect('database.db')
   cur = conn.cursor()
   cur.execute("SELECT * FROM Users WHERE id=?", (user_id,))
   user_data = cur.fetchone()
   conn.close()
   if user_data:
       user = User(user_data[0], user_data[1], user_data[2])  
       return user
   return None

# Registration form
class RegisterForm(FlaskForm):
   username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
   password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)])
   submit = SubmitField('Register')

# Login form
class LoginForm(FlaskForm):
   username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
   password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=20)])
   submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
   return render_template('home.html')
@app.route('/admin')
def admin():
   return render_template('admin.html', role='admin')


@app.route('/login', methods=['GET', 'POST'])
def login():
   form = LoginForm()
   if form.validate_on_submit():
       username = form.username.data
       password = form.password.data
       # Check if it's the admin trying to log in
       admin_username = 'admin'
       admin_password = 'adminpassword'  # Hash this password in a real scenario
       if username == admin_username and password == admin_password:
           # Redirect to admin dashboard
           return redirect(url_for('admin'))
       # Check for regular user login
       conn = sqlite3.connect('database.db')
       cur = conn.cursor()
       cur.execute("SELECT id, username, password, role FROM Users WHERE username=?", (username,))
       user_data = cur.fetchone()
       conn.close()
       if user_data:
           user_id, stored_username, stored_password, user_role = user_data
           if bcrypt.check_password_hash(stored_password, password):
               user_obj = User(user_id, stored_username, stored_password, user_role)
               login_user(user_obj)
               if user_role == 'admin':
                   return redirect(url_for('admin'))
               else:
                   return redirect(url_for('dashboard'))
           else:
               return "Invalid username or password"
       else:
           return "User does not exist. Please register."
   return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
   return render_template('dashboard.html', role='user')


@app.route('/logout')
def logout():
   return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
   form = RegisterForm()
   if form.validate_on_submit():
       username = form.username.data
       password = form.password.data
       hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
       conn = sqlite3.connect('database.db')
       cur = conn.cursor()
       cur.execute("INSERT INTO Users (username, password, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
       conn.commit()
       conn.close()
       return redirect(url_for('login'))
   return render_template('register.html', form=form)

#---------------------------------
 
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
cursor.execute('''
   CREATE TABLE IF NOT EXISTS Users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       username TEXT NOT NULL,
       password TEXT NOT NULL,
       role TEXT NOT NULL        
   )
''')
cursor.execute('''
   CREATE TABLE IF NOT EXISTS LeaveRequests (
       rowid INTEGER PRIMARY KEY AUTOINCREMENT,
       startdate TEXT NOT NULL,
       enddate TEXT NOT NULL,
       daterequested TEXT NOT NULL,
       requestcomments TEXT NOT NULL,
       approved TEXT NOT NULL,
       requestingemployee TEXT NOT NULL
   )
''')


"""
# Establish a connection to the SQLite database
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
try:
   # Execute the DROP TABLE statement to delete the LeaveRequest table
   cursor.execute("DROP TABLE IF EXISTS LeaveRequests")
   conn.commit()
   print("Table 'LeaveRequests' deleted successfully.")
except sqlite3.Error as e:
   print(f"SQLite error: {e}")
finally:
   conn.close()
"""
"""
# Query to fetch the table schema
cursor.execute("PRAGMA table_info('LeaveRequest')")
columns = cursor.fetchall()
# Print the columns and their details
print("Columns in LeaveRequest table:")
for column in columns:
   print(column)
conn.commit()
conn.close()
"""




#student data-----------------------------
@app.route("/enternew")
def enternew():
    return render_template("student.html")

# Route to add a new record (INSERT) student data to the database
@app.route("/addrec", methods = ['POST', 'GET'])
def addrec():
    # Data will be available from POST submitted by the form
    if request.method == 'POST':
        try:
            nm = request.form['nm']
            addr = request.form['add']
            city = request.form['city']
            zip = request.form['zip']

            # Connect to SQLite3 database and execute the INSERT
            with sqlite3.connect('database.db') as con:
                cur = con.cursor()
                cur.execute("INSERT INTO students (name, addr, city, zip) VALUES (?,?,?,?)",(nm, addr, city, zip))

                con.commit()
                msg = "Record successfully added to database"
        except:
            con.rollback()
            msg = "Error in the INSERT"

        finally:
            con.close()
            # Send the transaction message to result.html
            return render_template('result.html',msg=msg)

# Route to SELECT all data from the database and display in a table      
@app.route('/list')
def list():
    # Connect to the SQLite3 datatabase and 
    # SELECT rowid and all Rows from the students table.
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row

    cur = con.cursor()
    cur.execute("SELECT rowid, * FROM students")

    rows = cur.fetchall()
    con.close()
    # Send the results of the SELECT to the list.html page
    return render_template("list.html",rows=rows)

# Route that will SELECT a specific row in the database then load an Edit form 
@app.route("/edit", methods=['POST','GET'])
def edit():
   try:
       if request.method == 'POST':
           id = request.form['id']
           con = sqlite3.connect("database.db")
           con.row_factory = sqlite3.Row
           cur = con.cursor()
           cur.execute("SELECT rowid, * FROM students WHERE rowid = ?", (id,))
           rows = cur.fetchall()
           con.close()
           return render_template("edit.html", rows=rows)
   except sqlite3.Error as e:
       print(f"SQLite error: {e}")
   except Exception as ex:
       print(f"An error occurred: {ex}")
   return render_template("edit.html", rows=[])

# Route used to execute the UPDATE statement on a specific record in the database
@app.route("/editrec", methods=['POST','GET'])
def editrec():
    # Data will be available from POST submitted by the form
    if request.method == 'POST':
        try:
            # Use the hidden input value of id from the form to get the rowid
            rowid = request.form['rowid']
            nm = request.form['nm']
            addr = request.form['add']
            city = request.form['city']
            zip = request.form['zip']

            # UPDATE a specific record in the database based on the rowid
            with sqlite3.connect('database.db') as con:
                cur = con.cursor()
                cur.execute("UPDATE students SET name='"+nm+"', addr='"+addr+"', city='"+city+"', zip='"+zip+"' WHERE rowid="+rowid)

                con.commit()
                msg = "Record successfully edited in the database"
        except:
            con.rollback()
            msg = "Error in the Edit: UPDATE students SET name="+nm+", addr="+addr+", city="+city+", zip="+zip+" WHERE rowid="+rowid

        finally:
            con.close()
            # Send the transaction message to result.html
            return render_template('result.html',msg=msg)
        

@app.route("/delete", methods=['POST','GET'])
def delete():
    if request.method == 'POST':
        try:
             # Use the hidden input value of id from the form to get the rowid
            rowid = request.form['id']
            # Connect to the database and DELETE a specific record based on rowid
            with sqlite3.connect('database.db') as con:
                    cur = con.cursor()
                    cur.execute("DELETE FROM students WHERE rowid="+rowid)

                    con.commit()
                    msg = "Record successfully deleted from the database"
        except:
            con.rollback()
            msg = "Error in the DELETE"

        finally:
            con.close()
            # Send the transaction message to result.html
            return render_template('result.html',msg=msg)

#--------------------------------------
        




#Leavetype-----------------------------------
@app.route('/leavetype_details/<int:id>')
def leavetype_details(id):
   def get_leave_type_details_from_db(leave_id):
       conn = sqlite3.connect('database.db')
       conn.row_factory = sqlite3.Row  # Setting row_factory to fetch rows as dictionaries
       cur = conn.cursor()
       cur.execute("SELECT * FROM LeaveTypes WHERE rowid = ?", (leave_id,))
       leave_details = cur.fetchone()
       conn.close()
       return leave_details
   leavetype_details = get_leave_type_details_from_db(id)
   # Pass the fetched leave type details to the HTML template
   return render_template('Details.html', leavetype=leavetype_details)



@app.route("/enternewleave")
def enternewleave():
    return render_template("create.html")

# Route to add a new record (INSERT) student data to the database
@app.route("/addleaverec", methods = ['POST', 'GET'])
def addleaverec():
    # Data will be available from POST submitted by the form
    if request.method == 'POST':
        try:
            ltype = request.form['ltype']
            ddays = request.form['ddays']
            # Connect to SQLite3 database and execute the INSERT
            with sqlite3.connect('database.db') as con:
                cur = con.cursor()
                cur.execute("INSERT INTO LeaveTypes (leavetype, defaultdays) VALUES (?,?)",(ltype, ddays))

                con.commit()
                msg = "Record successfully added to database"
        except:
            con.rollback()
            msg = "Error in the INSERT"

        finally:
            con.close()
            # Send the transaction message to result.html
            return render_template('result.html',msg=msg)
        
# Route to SELECT all data from the database and display in a table      
@app.route('/leavetype')
def leavetype():
    # Connect to the SQLite3 datatabase and 
    # SELECT rowid and all Rows from the students table.
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row

    cur = con.cursor()
    cur.execute("SELECT rowid, * FROM LeaveTypes")

    rows = cur.fetchall()
    con.close()
    # Send the results of the SELECT to the list.html page
    return render_template("leavetype.html",rows=rows)


@app.route("/editleave", methods=['POST','GET'])
def editleave():
   try:
       if request.method == 'POST':
           id = request.form['id']
           con = sqlite3.connect("database.db")
           con.row_factory = sqlite3.Row
           cur = con.cursor()
           cur.execute("SELECT rowid, * FROM LeaveTypes WHERE rowid = ?", (id,))
           rows = cur.fetchall()
           con.close()
           return render_template("editleave.html", rows=rows)
   except sqlite3.Error as e:
       print(f"SQLite error: {e}")
   except Exception as ex:
       print(f"An error occurred: {ex}")
   return render_template("editleave.html", rows=[])

# Route used to execute the UPDATE statement on a specific record in the database
@app.route("/editleaverec", methods=['POST'])
def editleaverec():
   if request.method == 'POST':
       try:
           rowid = request.form['rowid']
           ltype = request.form['ltype']
           ddays = request.form['ddays']
           with sqlite3.connect('database.db') as con:
               cur = con.cursor()
               cur.execute("UPDATE LeaveTypes SET leavetype=?, defaultdays=? WHERE rowid=?", (ltype, ddays, rowid))
               con.commit()
           return redirect(url_for('leavetype'))  # Redirect to 'leavetype' route
       except Exception as e:
           return jsonify({"message": f"Error in the Edit: {str(e)}"})
        

@app.route("/deleteleave", methods=['POST'])
def deleteleave():
   if request.method == 'POST':
       try:
           rowid = request.form.get('id')
           if rowid:
               with sqlite3.connect('database.db') as con:
                   cur = con.cursor()
                   cur.execute("DELETE FROM LeaveTypes WHERE rowid=?", (rowid,))
                   con.commit()
               return redirect(url_for('leavetype'))  
           else:
               return jsonify({"message": "No ID provided for deletion"})
       except Exception as e:
           return jsonify({"message": f"Error in deletion: {str(e)}"})
       


#-------------------------------
      




#leave request------------------------
@app.route("/enternewleavereq")
def enternewleavereq():
    return render_template("createreq.html")

# Route to add a new record (INSERT) student data to the database
@app.route("/addleavereqrec", methods=['POST', 'GET'])
def addleavereqrec():
   msg = None  # Initialize message variable
   if request.method == 'POST':
       try:
           sdate = request.form['sdate']
           edate = request.form['edate']
           drequested = request.form['drequested']
           rcomments = request.form['rcomments']
           approve = request.form['approve']
           reqemp = request.form['reqemp']
           with sqlite3.connect('database.db') as con:
               cur = con.cursor()
               cur.execute("INSERT INTO LeaveRequests (startdate, enddate, daterequested, requestcomments, approved, requestingemployee) VALUES (?, ?, ?, ?, ?, ?)", (sdate, edate, drequested, rcomments, approve, reqemp))
               con.commit()
               msg = "Record successfully added to the database"
               return redirect(url_for('leaverequest'))  # Redirect to 'leaverequest' route after adding record
       except sqlite3.Error as e:
           msg = f"SQLite error: {e}"
       except Exception as ex:
           msg = f"An error occurred: {ex}"
   return render_template('result.html', msg=msg)
       
# Route to SELECT all data from the database and display in a table      
@app.route('/leaverequest')
def leaverequest():
    # Connect to the SQLite3 datatabase and 
    # SELECT rowid and all Rows from the students table.
    con = sqlite3.connect("database.db")
    con.row_factory = sqlite3.Row

    cur = con.cursor()
    cur.execute("SELECT rowid, * FROM LeaveRequests")

    rows = cur.fetchall()
    con.close()
    # Send the results of the SELECT to the list.html page
    return render_template("leaverequest.html",rows=rows)


@app.route("/editleavereq", methods=['POST','GET'])
def editleavereq():
   try:
       if request.method == 'POST':
           id = request.form['id']
           con = sqlite3.connect("database.db")
           con.row_factory = sqlite3.Row
           cur = con.cursor()
           cur.execute("SELECT rowid, * FROM LeaveRequests WHERE rowid = ?", (id,))
           rows = cur.fetchall()
           con.close()
           return render_template("editleavereq.html", rows=rows)
   except sqlite3.Error as e:
       print(f"SQLite error: {e}")
   except Exception as ex:
       print(f"An error occurred: {ex}")
   return render_template("editleavereq.html", rows=[])

@app.route("/deleteleavereq", methods=['POST'])
def deleteleavereq():
   if request.method == 'POST':
       try:
           rowid = request.form.get('id')
           if rowid:
               with sqlite3.connect('database.db') as con:
                   cur = con.cursor()
                   cur.execute("DELETE FROM LeaveRequests WHERE rowid=?", (rowid,))
                   con.commit()
               return redirect(url_for('leaverequest'))  
           else:
               return jsonify({"message": "No ID provided for deletion"})
       except Exception as e:
           return jsonify({"message": f"Error in deletion: {str(e)}"})


# Your existing route to render the template with leave requests
@app.route('/MyLeavee')
def MyLeavee():
   con = sqlite3.connect("database.db")
   con.row_factory = sqlite3.Row
   cur = con.cursor()
   cur.execute("SELECT rowid, * FROM LeaveRequests")
   rows = cur.fetchall()
   con.close()
   return render_template("MyLeavee.html", rows=rows)
# New route to handle status update requests via AJAX
@app.route('/update_status', methods=['POST'])
def update_status():
   # Retrieve data from the request (row ID and status)
   row_id = request.form.get('row_id')
   status = request.form.get('status')
   # Update the status in your database (SQLite in this case)
   con = sqlite3.connect("database.db")
   cur = con.cursor()
   cur.execute("UPDATE LeaveRequests SET approved = ? WHERE rowid = ?", (status, row_id))
   con.commit()
   con.close()
   # Return a success response indicating the status was updated
   return jsonify({'message': 'Status updated successfully'})


#---------------------------------------




#users------------------------------------------

# Route to display the table
@app.route('/Employee')
def display_employee_table():
   conn = sqlite3.connect('database.db')
   cursor = conn.cursor()
   # Fetch data from the Users table including rowid
   cursor.execute("SELECT rowid, * FROM Users")
   rows = cursor.fetchall()
   conn.close()
   return render_template('Employee.html', rows=rows)

#-----------------------------------------

if __name__ == '__main__':
   app.run(debug=True)
        

        