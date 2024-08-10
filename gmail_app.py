import os
from flask import Flask, render_template, url_for, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user 
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from simplegmail import Gmail
import json
from pathlib import Path
import joblib
from preprocessor import Preprocessor
from textblob import TextBlob
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

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

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("Username taken, please use a different one.")
        
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session['username'] = form.username.data
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username and/or password, try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    username = session.get('username')
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for('login'))

    
    tokenFileName = f'gmail_token_{username}.json'
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

    messages = gmail.get_important_messages()
    
    
    negative = []
    neutral = []
    positive = []
    
    length = min(100, len(messages))

    for message in messages[:length]:
        try:
            text = message.plain
            sentimentScore = analyseSentiment(text)
            if -0.4 <= sentimentScore <= 0.4:
                neutral.append(message)
            elif sentimentScore > 0.4:
                positive.append(message)
            else:
                negative.append(message)
        except Exception as e:
            print(f"Error processing text: {e}")
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
    session.clear()
    if Path('gmail_token.json').is_file():
        os.remove('gmail_token.json')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

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
    username = session.get('username')
    gmail = Gmail(creds_file=f'gmail_token_{username}.json')
    messages = gmail.get_important_messages()

    email_dictionary = {message.id: message for message in messages if message}

    email = email_dictionary.get(email_id)

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
    print(f'vader sentiment: {vaderSentiment}')
    
    vectorizedText = vectorizer.transform([text])
    modelPrediction = model.predict(vectorizedText)[0] - 1
    print(f'model prediction: {modelPrediction}')
    
    blob = TextBlob(text)
    numSentences = len(blob.sentences)
    total = 0
    for sentence in blob.sentences:
        total += sentence.sentiment.polarity
    blobSentiment = total / numSentences
    
    print(f'blob sentiment: {blobSentiment}')
    
    weightedSum = (weights['vader'] * vaderSentiment +
                   weights['textblob'] * blobSentiment +
                   weights['model'] * modelPrediction)
    
    print(f'weighted sum: {weightedSum}')
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
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)