import os
from flask import Flask, render_template, url_for, redirect, session, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user 
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from simplegmail import Gmail
import json
from pathlib import Path
import joblib
from preprocessor import Preprocessor
from textblob import TextBlob
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from datetime import datetime
from sqlalchemy.exc import SQLAlchemyError
import re
from sqlalchemy.types import TypeDecorator, String
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)
db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SECRET_KEY'] = 'mysecretkey'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
wordProcessor = Preprocessor()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def getCreateKey(file_path="key.txt"):
    try:
        with open(file_path, "r") as f:
            key = f.read().strip()
        print("Key loaded from file.")
    except FileNotFoundError:
        key = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
        with open(file_path, "w") as f:
            f.write(key)
        print("New key generated and saved.")
    return key

class baseDatabaseModel(db.Model):
    __abstract__ = True
    createdAt = db.Column(db.DateTime, default=datetime.now)
    updatedAt = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)

class encryptedType(TypeDecorator):
    impl = String

    def __init__(self, *args, **kwargs):
        self.key = getCreateKey()
        self.fernet = Fernet(self.key)
        super().__init__(*args, **kwargs)
    
    def process_bind_param(self, value, dialect):
        if value is not None:
            value = self.fernet.encrypt(value.encode()).decode()
        return value
    
    def process_result_value(self, value, dialect):
        if value is not None:
            value = self.fernet.decrypt(value.encode()).decode()
        return value

class User(baseDatabaseModel, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    credentials = db.Column(encryptedType, nullable=True)
    emailsLoaded = db.Column(db.DateTime, nullable=True)
    emails = db.relationship('Email', back_populates='user', cascade='all, delete-orphan')
    securityQuestion = db.Column(db.String(50), nullable=True)
    securityAnswer = db.Column(db.String(120), nullable=True)
    passwordAttempts = db.Column(db.Integer, nullable=False, default=0)
    locked = db.Column(db.Boolean, nullable=False, default=False)
    type = db.Column(db.Integer, nullable=False)
    lastLogin = db.Column(db.DateTime, nullable=True)

class Email(baseDatabaseModel):
    id = db.Column(db.String(32), primary_key=True)
    sender = db.Column(db.String(320), nullable=False)
    date = db.Column(db.DateTime())
    subject = db.Column(db.String(255), nullable=False)
    plain = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(10), nullable=True)
    snippet = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(20), db.ForeignKey('user.username'), nullable=False)
    user = db.relationship('User', back_populates='emails')

class baseForm(FlaskForm):
    def __init__(self, *args, **kwargs):
        super(baseForm, self).__init__(*args, **kwargs)
        
class registrationForm(baseForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    
    securityQuestion = SelectField(
        'Security Question',
        choices=[
            ('motherMaiden', 'What is your mother\'s maiden name?'),
            ('firstPet', 'What was your first pet\'s name?'),
            ('homeTown', 'What city/town were you born in?')
        ],
        validators=[InputRequired()]
    )
    
    securityAnswer = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Answer"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existingUserUsername = User.query.filter_by(username=username.data).first()

        if existingUserUsername:
            raise ValidationError("Username taken, please use a different one.")
        
class loginForm(baseForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

class forgotPasswordForm(baseForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={'placeholder': 'Username'})
    
    submit = SubmitField('Reset Password')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if not existing_user_username:
            raise ValidationError("No account with that username found, try again.")

class resetPasswordForm(baseForm):
    securityAttempt = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Answer"})
    
    newPassword = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': 'New Password'})
    
    confirmPassword = PasswordField(validators=[InputRequired(), EqualTo('newPassword', message='Passwords must match.')], render_kw={'placeholder': 'Confirm password'})
    
    submit = SubmitField('Change Password')

class resetUserPasswordForm(baseForm):
    newPassword = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': 'New Password'})
    
    confirmPassword = PasswordField(validators=[InputRequired(), EqualTo('newPassword', message='Passwords must match.')], render_kw={'placeholder': 'Confirm password'})
    
    submit = SubmitField('Reset Password')

class editUsernameForm(baseForm):
    newUsername = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': 'New Username'})
    
    submit = SubmitField('Change Username')

    def validate_username(self, newUsername):
        existingUserUsername = User.query.filter_by(username=newUsername.data).first()

        if existingUserUsername:
            raise ValidationError("Username taken, please use a different one.")

class RegisterAdminForm(baseForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existingUserUsername = User.query.filter_by(username=username.data).first()

        if existingUserUsername:
            raise ValidationError("Username taken, please use a different one.")

class sendEmailForm(baseForm):
    
    subject = StringField(validators=[InputRequired(), Length(min=1, max=255)], render_kw={'placeholder': 'Subject'})
    
    message = TextAreaField(validators=[InputRequired()], render_kw={'placeholder': 'Message', "class": "largeTextbox", "wrap": "soft"})
    
    submit = SubmitField('Send Email')
    
        

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = registrationForm()

    if form.validate_on_submit():
        try:
            hashedPassword = bcrypt.generate_password_hash(form.password.data)
            hashedAnswer = bcrypt.generate_password_hash(form.securityAnswer.data)
            newUser = User(username=form.username.data, 
                            password=hashedPassword,
                            securityQuestion = form.securityQuestion.data, 
                            securityAnswer = hashedAnswer,
                            type=1
                            )
            db.session.add(newUser)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback
            app.logger.error(f"Database error: {str(e)}")
            flash('An error occurred while processing your request. Please try again later.', 'danger')
            return render_template('register.html', form=form)

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = loginForm()
    if '/resetPassword/' in request.referrer and session.get('PasswordChanged'):
        flash('Password successfully changed', 'green')
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.locked:
            flash('Account locked', 'danger')
            return redirect(url_for('login'))
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session['username'] = form.username.data
            
            if user.type == 1:
                return redirect(url_for('loading'))
            else:
                return redirect(url_for('adminDashboard'))
        else:
            if user:
                user.passwordAttempts += 1
                if user.passwordAttempts >= 5:
                    user.locked = True
                    db.session.commit()
                    flash('Account locked due to too many failed login attempts', 'danger')
                    return redirect(url_for('login'))
                db.session.commit()
            flash('Invalid username and/or password, try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/sendEmail/<recipient>', methods=['GET', 'POST'])
@login_required
def sendEmail(recipient):
    form = sendEmailForm()
    recipientEmail = re.search(r'<.*?>', recipient)
    username = session.get('username')
    if form.validate_on_submit():
        gmail = Gmail(creds_file=f'gmail_token_{username}.json')
        
        gmail.send_message(
            subject=form.subject.data,
            msg_html=form.message.data,
            sender='me',
            to=recipientEmail.group(0)[1:-1]
        )
        return redirect(url_for('dashboard'))
    return render_template('sendEmail.html', form=form)


@app.route('/forgotPassword', methods=['GET', 'POST'])
def forgotPassword():
    form = forgotPasswordForm()
    if form.validate_on_submit():
        username = form.username.data
    
        return redirect(url_for('resetPassword', username=username))
    
    return render_template('forgotPassword.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    username = session.get('username')
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for('login'))
    
    user.lastLogin = datetime.now()
    
    reload = session.get('reloadEmails', False)

    passwordAttempts = user.passwordAttempts
    user.passwordAttempts = 0
    db.session.commit()

    if not user.emailsLoaded or (datetime.now() - user.emailsLoaded).total_seconds() > 86400 or reload:
        messages = initialLoad(user)
        existingEmailIds = {email.id for email in Email.query.with_entities(Email.id).all()}
        emailsToAdd = [message for message in messages if message.id not in existingEmailIds]
        session['reloadEmails'] = False

        if emailsToAdd:
            try:
                addNewEmails(user, emailsToAdd)
                user.emailsLoaded = datetime.now()
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                app.logger.error(f"Database error: {str(e)}")
                flash('An error occurred while processing your request. Please try again later.', 'danger')
                return render_template(url_for('dashboard'))
            negative, neutral, positive = assignSentiments(messages)
        else:
            emails = Email.query.filter_by(username=username).all()
            negative = [message for message in emails if message.sentiment == 'negative']
            neutral = [message for message in emails if message.sentiment == 'neutral']
            positive = [message for message in emails if message.sentiment == 'positive']
    else:
        loadCredFile(user)
        emails = Email.query.filter_by(username=username).all()
        negative = [message for message in emails if message.sentiment == 'negative']
        neutral = [message for message in emails if message.sentiment == 'neutral']
        positive = [message for message in emails if message.sentiment == 'positive']
    
    categorisedMessages = {
        'positive': positive,
        'negative': negative,
        'neutral': neutral
    }

    return render_template('dashboard.html', username=username, categorisedMessages = categorisedMessages, passwordAttempts=passwordAttempts)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    username = session.get('username')
    session.clear()
    if Path('gmail_token.json').is_file():
        os.remove('gmail_token.json')
    if Path(f'gmail_token_{username}.json').is_file():
        os.remove(f'gmail_token_{username}.json')
    return redirect(url_for('home'))

@app.route('/adminDashboard', methods=['GET', 'POST'])
@login_required
def adminDashboard():
    return render_template('adminDashboard.html')

@app.route('/adminDataPage', methods=['GET', 'POST'])
@login_required
def adminDataPage():

    overallSentimentCounts = {
        'positive': Email.query.filter_by(sentiment='positive').count(),
        'negative': Email.query.filter_by(sentiment='negative').count(),
        'neutral': Email.query.filter_by(sentiment='neutral').count()
    }

    users = User.query.all()
    return None

@app.route('/adminUserManagement', methods=['GET', 'POST'])
@login_required
def adminUserManagement():
    users = User.query.all()
    return render_template('adminUserManagement.html', users=users)

@app.route('/adminUserManagement/<username>', methods=['GET', 'POST'])
@login_required
def adminUserManagementUser(username):
    user = User.query.filter_by(username=username).first()
    return render_template('adminUserManagementUser.html', user=user)

@app.route('/deleteUser/<username>', methods=['GET', 'POST'])
@login_required
def deleteUser(username):
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
    return redirect(url_for('adminUserManagement'))

@app.route('/resetUserPassword/<username>', methods=['GET', 'POST'])
@login_required
def resetUserPassword(username):
    form = resetUserPasswordForm()
    user = User.query.filter_by(username=username).first()
    if form.validate_on_submit():
        hashedPassword = bcrypt.generate_password_hash(form.newPassword.data)
        user.password = hashedPassword
        db.session.commit()
        return redirect(url_for('adminUserManagement'))
    return render_template('resetUserPassword.html', form=form, user=user)

@app.route('/editUsername/<username>', methods=['GET', 'POST'])
@login_required
def editUsername(username):
    form = editUsernameForm()
    user = User.query.filter_by(username=username).first()
    if form.validate_on_submit():
        user.username = form.newUsername.data
        db.session.commit()
        return redirect(url_for('adminUserManagement'))
    return render_template('editUsername.html', form=form, user=user)

@app.route('/registerAdmin', methods=['GET', 'POST'])
@login_required
def registerAdmin():
    form = RegisterAdminForm()
    if form.validate_on_submit():
        try:
            hashedPassword = bcrypt.generate_password_hash(form.password.data)
            newUser = User(username=form.username.data, 
                            password=hashedPassword,
                            type=2
                            )
            db.session.add(newUser)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback
            app.logger.error(f"Database error: {str(e)}")
            flash('An error occurred while processing your request. Please try again later.', 'danger')
            return render_template('registerAdmin.html', form=form)

        return redirect(url_for('adminUserManagement'))

    return render_template('registerAdmin.html', form=form)

@app.route('/deleteAccount', methods=['GET', 'POST'])
@login_required
def deleteAccount():
    username = session.get('username')
    user = User.query.filter_by(username=username).first()
    if user:
        db.session.delete(user)
        db.session.commit()
    
    return redirect(url_for('logout'))

@app.route('/user/<username>')
@login_required
def userProfile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found", 404

    sentimentCounts = {
        'positive': Email.query.filter_by(username=username, sentiment='positive').count(),
        'negative': Email.query.filter_by(username=username, sentiment='negative').count(),
        'neutral': Email.query.filter_by(username=username, sentiment='neutral').count()
    }

    return render_template('userprofile.html', user=user, sentimentCounts=sentimentCounts)

@app.route('/email/<email_id>')
@login_required
def view_email(email_id):
    
    email = Email.query.filter_by(id=email_id).first()

    return render_template('email.html', email=email)

def analyseSentiment(text):
    weights = {
        'vader': 0.5,
        'textblob': 0.3,
        'model': 0.2
    }
    
    text = wordProcessor.tokenize(wordProcessor.cleanText(text))
    vaderAnalyser = SentimentIntensityAnalyzer()
    vectorizer = joblib.load('EmailModel vectorizer.pkl')
    model = joblib.load('EmailModel.pkl')
    
    
    vaderSentiment = vaderAnalyser.polarity_scores(text)['compound']
    
    vectorizedText = vectorizer.transform([text])
    modelPrediction = model.predict(vectorizedText)[0] - 1
    
    blob = TextBlob(text)
    numSentences = len(blob.sentences)
    total = 0
    for sentence in blob.sentences:
        total += sentence.sentiment.polarity
    blobSentiment = total / numSentences
    
    weightedSum = (weights['vader'] * vaderSentiment +
                   weights['textblob'] * blobSentiment +
                   weights['model'] * modelPrediction)
    
    return weightedSum

@app.route('/linkNew')
@login_required
def linkNew():
    if Path('gmail_token.json').is_file():
        os.remove('gmail_token.json')
    username = session.get('username')
    tokenFileName = f'gmail_token_{username}.json'
    if Path(tokenFileName).is_file():
        os.remove(tokenFileName)
    user = User.query.filter_by(username=username).first()
    user.credentials = None
    emails = Email.query.filter_by(username=username).all()
    try:
        for email in emails:
            db.session.delete(email)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Database error: {str(e)}")
        flash('An error occurred while processing your request. Please try again later.', 'danger')
        return render_template(url_for('loading'))
    session['reloadEmails'] = True
    
    return redirect(url_for('loading'))

@app.route('/reset/<username>', methods=['GET', 'POST'])
@login_required
def reset(username):
    user = User.query.filter_by(username=username).first()
    form = resetUserPasswordForm()
    if form.validate_on_submit():
        hashedPassword = bcrypt.generate_password_hash(form.newPassword.data)
        user.password = hashedPassword
        db.session.commit()
        if user.type == 1:
            return redirect(url_for('loading'))
        else:
            return redirect(url_for('adminUserManagement'))
        
    return render_template('reset.html', form=form, user=user)
    

@app.route('/deleteEmail/<email_id>')
@login_required
def deleteEmail(email_id):
    username = session.get('username')
    email = Email.query.filter_by(id=email_id).first()
    if email:
        db.session.delete(email)
        db.session.commit()
    gmail = Gmail(creds_file=f'gmail_token_{username}.json')
    messages = gmail.get_messages(query='category:primary')

    email_dictionary = {message.id: message for message in messages if message}

    email = email_dictionary.get(email_id)
    
    email.move_from_inbox(to='TRASH')
    
    return redirect(url_for('loading'))

@app.route('/reload')
def reload():
    session['reloadEmails'] = True
    return redirect(url_for('loading'))

@app.route('/loading')
def loading():
    return render_template('loading.html')

@app.route('/resetPassword/<username>', methods=['GET', 'POST'])
def resetPassword(username):
    form = resetPasswordForm()
    user = User.query.filter_by(username=username).first()
    choices = {'motherMaiden': 'What is your mother\'s maiden name?',
                'firstPet': 'What was your first pet\'s name?',
                'homeTown': 'What city/town were you born in?'}
    
    if form.validate_on_submit():
        hashedAnswer = bcrypt.check_password_hash(user.securityAnswer, form.securityAttempt.data)
        same = bcrypt.check_password_hash(user.password, form.newPassword.data)
        if hashedAnswer:
            if not same:
                try:
                    newPasswordHashed = bcrypt.generate_password_hash(form.newPassword.data)
                    user.password = newPasswordHashed
                    db.session.commit()
                    session['PasswordChanged'] = True
                    return redirect(url_for('login'))
                except SQLAlchemyError as e:
                    db.session.rollback()
                    app.logger.error(f"Database error: {str(e)}")
                    flash('An error occurred while processing your request. Please try again later.', 'danger')
            else:
                flash('You cannot use the same password as before.', 'danger')
                return render_template('resetPassword.html', form=form, questions=choices[user.securityQuestion])
        else:
            flash('Incorrect answer to security question, Try again.', 'danger')
    
    return render_template('resetPassword.html', form=form, question=choices[user.securityQuestion])

def assignSentiments(messages):
    negative = []
    neutral = []
    positive = []
    
    length = min(100, len(messages))

    for message in messages[:length]:
        try:
            text = message.plain
            email = Email.query.filter_by(id=message.id).first()
            sentimentScore = analyseSentiment(text)
            if -0.4 <= sentimentScore <= 0.4:
                neutral.append(message)
                email.sentiment = 'neutral'
            elif sentimentScore > 0.4:
                positive.append(message)
                email.sentiment = 'positive'
            else:
                email.sentiment = 'negative'
                negative.append(message)
            db.session.commit()
        except Exception as e:
            print(f"Error processing text: {e}")
    
    return negative, neutral, positive

def addNewEmails(user, emailsToAdd):
    
    for email in emailsToAdd:
        try:
            if not email.plain:
                continue
            new_email = Email(
                id=email.id,
                sender=email.sender,
                date=datetime.fromisoformat(email.date),
                subject=email.subject,
                plain=email.plain,
                username = user.username,
                snippet=email.snippet
            )
            
            db.session.add(new_email)
            db.session.commit()
        except Exception as e:
            print(e)

def initialLoad(user):
    tokenFileName = f'gmail_token_{user.username}.json'
    if user.credentials:
        if not Path(tokenFileName).is_file():
            with open(tokenFileName, 'w') as gmailtoken:
                json.dump(json.loads(user.credentials), gmailtoken)
    else:
        gmail = Gmail()
        user.credentials = gmail.creds.to_json()
        db.session.commit()
        with open(tokenFileName, 'w') as gmailtoken:
            json.dump(json.loads(user.credentials), gmailtoken)
    
    gmail = Gmail(creds_file=tokenFileName)

    messages = gmail.get_messages()
    
    return messages

def loadCredFile(user):
    tokenFileName = f'gmail_token_{user.username}.json'
    
    if user.credentials:
        if not Path(tokenFileName).is_file():
            with open(tokenFileName, 'w') as gmailtoken:
                json.dump(json.loads(user.credentials), gmailtoken)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        adminAccount = User.query.filter_by(username = 'admin1').first()
        if not adminAccount:
            hashedPassword = bcrypt.generate_password_hash('34fjbn6943')
            newUser = User(username='admin1', 
                            password=hashedPassword,
                            type=2
                            )
            db.session.add(newUser)
            db.session.commit()
            for i in range(2,15):
                newUser = User(username=f'admin{i}', 
                            password=hashedPassword,
                            type=2
                            )
                db.session.add(newUser)
                db.session.commit()

    app.run(debug=True)