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

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    credentials = db.Column(db.Text, nullable=True)
    emails_loaded = db.Column(db.DateTime, nullable=True)
    emails = db.relationship('Email', back_populates='user', cascade='all, delete-orphan')
    securityQuestion = db.Column(db.String(50), nullable=False)
    securityAnswer = db.Column(db.String(120), nullable=False)

class Email(db.Model):
    id = db.Column(db.String(32), primary_key=True)
    sender = db.Column(db.String(320), nullable=False)
    date = db.Column(db.DateTime())
    subject = db.Column(db.String(255), nullable=False)
    plain = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(10), nullable=True)
    snippet = db.Column(db.Text, nullable=False)
    username = db.Column(db.String(20), db.ForeignKey('user.username'), nullable=False)
    user = db.relationship('User', back_populates='emails')

class RegistrationForm(FlaskForm):
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
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("Username taken, please use a different one.")
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

class forgotPasswordForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=20)], render_kw={'placeholder': 'Username'})
    
    submit = SubmitField('Reset Password')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if not existing_user_username:
            raise ValidationError("No account with that username found, try again.")

class resetPasswordForm(FlaskForm):
    securityAttempt = StringField(validators=[InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "Answer"})
    
    newPassword = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder': 'New Password'})
    
    confirmPassword = PasswordField(validators=[InputRequired(), EqualTo('newPassword', message='Passwords must match.')], render_kw={'placeholder': 'Confirm password'})
    
    submit = SubmitField('Change Password')

class sendEmailForm(FlaskForm):
    
    subject = StringField(validators=[InputRequired(), Length(min=1, max=255)], render_kw={'placeholder': 'Subject'})
    
    message = TextAreaField(validators=[InputRequired()], render_kw={'placeholder': 'Message', "class": "largeTextbox", "wrap": "soft"})
    
    submit = SubmitField('Send Email')
    
        

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if '/resetPassword/' in request.referrer and session.get('PasswordChanged'):
        flash('Password successfully changed', 'green')
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session['username'] = form.username.data
            
            return redirect(url_for('loading'))
        else:
            flash('Invalid username and/or password, try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/sendEmail/<recipient>', methods=['GET', 'POST'])
def sendEmail(recipient):
    form = sendEmailForm()
    recipientEmail = re.search(r'<.*?>', recipient)
    if form.validate_on_submit():
        gmail = Gmail(creds_file='gmail_token.json')
        
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
    
    reload = session.get('reloadEmails', False)

    if not user.emails_loaded or (datetime.now() - user.emails_loaded).total_seconds() > 86400 or reload:
        messages = initialLoad(user)
        existingEmailIds = {email.id for email in Email.query.with_entities(Email.id).all()}
        emailsToAdd = [message for message in messages if message.id not in existingEmailIds]
        session['reloadEmails'] = False

        if emailsToAdd:
            try:
                addNewEmails(user, emailsToAdd)
                user.emails_loaded = datetime.now()
                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                app.logger.error(f"Database error: {str(e)}")
                flash('An error occurred while processing your request. Please try again later.', 'danger')
                return render_template(url_for('dashboard'))
            negative, neutral, positive = assignSentiments(messages)
        else:
            negative, neutral, positive = [], [], []
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

    return render_template('dashboard.html', username=username, categorisedMessages = categorisedMessages)

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

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            hashedAnswer = bcrypt.generate_password_hash(form.securityAnswer.data)
            new_user = User(username=form.username.data, 
                            password=hashed_password,
                            securityQuestion = form.securityQuestion.data, 
                            securityAnswer = hashedAnswer
                            )
            db.session.add(new_user)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback
            app.logger.error(f"Database error: {str(e)}")
            flash('An error occurred while processing your request. Please try again later.', 'danger')
            return render_template(url_for('register'), form=form)

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/user/<username>')
@login_required
def user_profile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "User not found", 404

    return render_template('userprofile.html', user=user)

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

@app.route('/deleteEmail/<email_id>')
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

    messages = gmail.get_messages(query='category:primary')
    
    return messages

def loadCredFile(user):
    tokenFileName = f'gmail_token_{user.username}.json'
    
    if user.credentials:
        if not Path(tokenFileName).is_file():
            with open(tokenFileName, 'w') as gmailtoken:
                json.dump(json.loads(user.credentials), gmailtoken)

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
                flash('That is the same password you had before monkey', 'danger')
        else:
            flash('Incorrect answer to security question, Try again', 'danger')
    
    return render_template('resetPassword.html', form=form, question=choices[user.securityQuestion])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)