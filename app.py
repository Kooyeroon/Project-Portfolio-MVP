from flask import Flask, render_template, redirect, url_for, session, flash, request, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flask_mysqldb import MySQL
from flask_login import login_user, logout_user, login_required

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'sql8.freemysqlhosting.net'
app.config['MYSQL_USER'] = 'sql8688311'
app.config['MYSQL_PASSWORD'] = 'gx8ckXm9fr'
app.config['MYSQL_DB'] = 'sql8688311'
app.secret_key = 'goshukenea36'

mysql = MySQL(app)

class RegisterForm(FlaskForm):
    name = StringField("Name",validators=[DataRequired()])
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self,field):
        cursor = mysql.connection.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255),
                    email VARCHAR(255),
                    password VARCHAR(255)
                )''')

        cursor.execute("SELECT * FROM users where email=%s",(field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')


class LoginForm(FlaskForm):
    email = StringField("Email",validators=[DataRequired(), Email()])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("Login")



@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        hashed_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())

        # store data into database 
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name,email,password) VALUES (%s,%s,%s)",(name,email,hashed_password))
        mysql.connection.commit()
        cursor.close()

        return redirect(url_for('login'))

    return render_template('register.html',form=form)

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s",(email,))
        user = cursor.fetchone()
        cursor.close()
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('beam'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html',form=form)


@app.route('/beam')
def beam():
    return render_template('beam.html')


@app.route('/calculate', methods=['POST'])
def calculate():
    l = float(request.form['length'])
    st = request.form['support_type']
    lm = float(request.form['load_magnitude'])
    lp = float(request.form['load_position'])

    segment_length = l / 200
    shear_force = []
    bending_moment = []

    if st == "Pin-Pin":
        for i in range(201):
            p = i * segment_length

            # Calculate shear force
            if p <= lp:
                shear_force.append(lm * (1 - lp / l))
            else:
                shear_force.append(-lm * (lp / l))


            # Calculate bending moment
            if p <= lp:
                bending_moment.append(p * lm * (1 - lp / l))
            else:
                bending_moment.append(lm * lp * (1 - p / l))

    elif st == "Pin-Fixed":
        for i in range(201):
            p = i * segment_length

            # Calculate shear force
            if p <= lp:
                shear_force.append(((lm * (l - lp)**2) * (lp + 2 * l))/(2 * l**3))
            else:
                shear_force.append(-((lm * lp) * (3 * l**2 - lp**2))/(2 * l**3))


            # Calculate bending moment
            if p <= lp:
                bending_moment.append(p * ((lm * (l - lp)**2) * (lp + 2 * l))/(2 * l**3))
            else:
                bending_moment.append((p * ((lm * (l - lp)**2) * (lp + 2 * l))/(2 * l**3)) - (lm* (p-lp)))

    elif st == "Fixed-Pin":
        for i in range(201):
            p = i * segment_length

            # Calculate shear force
            if p <= lp:
                shear_force.append((lm * (l - lp) * (3 * l**2 - (l - lp)**2)) / (2* l**3))
            else:
                shear_force.append(-((lm * lp**2) * ((l - lp) + 2 * l)) / (2 * l**3))


            # Calculate bending moment
            if p <= lp:
                bending_moment.append(p * ((lm* (l - lp) * (3 * l**2 - (l - lp)**2))/(2*l**3))-((lm*lp*(l-lp)*(2*l - lp))/(2*l**2)))
            else:
                bending_moment.append(p * ((lm* (l - lp) * (3 * (l - lp)**2 - (l - lp)**2))/(2*l**3))-((lm*lp*(l-lp)*(2*l - lp))/(2*l**2))-(lm*(p - (l - lp))))

    else:
        for i in range(201):
            p = i * segment_length

            # Calculate shear force
            if p <= lp:
                shear_force.append((lm* (3*lp + (l - lp))*(l-lp)**2)/(l**3))           
            else:
                shear_force.append(-(lm* (lp + 3*(l - lp))*(lp)**2)/(l**3))


            # Calculate bending moment
            if p <= lp:
                bending_moment.append((p * (lm * (3 * lp + (l - lp)) * (l-lp)**2) / (l**3)) - ((lm * lp * (l - lp)**2) / (l**2)))
            else:
                bending_moment.append((p * (lm * (3 * lp + (l - lp)) * (l-lp)**2) / (l**3)) - ((lm * lp * (l - lp)**2) / (l**2)) - (lm * (p - lp)))

    # Create in MySQL database
    cursor = mysql.connection.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS beam_loads (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    position FLOAT(10),
                    shear_force FLOAT(10),
                    bending_moment FLOAT(10)
                )''')

    # Store in MySQL database

    for i in range(201):
        position = i * l / 200
        cursor = mysql.connection.cursor()
        query = "INSERT INTO beam_loads (position, shear_force, bending_moment) VALUES (%s, %s, %s)"
        cursor.execute(query, (position, shear_force[i], bending_moment[i]))
        mysql.connection.commit()
        cursor.close()

    flash('Congratulations! Your calculation is successful! and sent to MySQL database', 'success')

    return redirect(url_for('beam'))


@app.route('/diagram', methods = ['GET', 'POST'])
def diagram():
    # Fetch data from MySQL
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT position, shear_force, bending_moment FROM beam_loads")
    data = cursor.fetchall()
    cursor.close()
    return render_template('diagram.html', beam_data=data)
    

@app.route('/download')
def download():
    return render_template('download.html')


@app.route('/clear_data', methods = ['POST'])
def clear_data():
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM beam_loads")
    mysql.connection.commit()
    cursor.close()

    session.pop('user_id', None)
    flash("Data cleared successfully!")
    return redirect(url_for('beam'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug =True)