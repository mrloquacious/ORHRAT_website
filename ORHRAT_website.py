import webapp2
import re
import random
import string
import hashlib
import os
import jinja2
import hmac
from google.appengine.ext import db
from module import SECRET

# Set up the Jinja2 template filesystem:
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# The expression *a means the function will take any number of arguments, while **kw means it will take any number of keyword arguments. Functionally, it doesn't matter what the trailing letters are, just what number of asterisks. The form username="" is a keyword argument.
# Helper functions for using Jinja2 templates:
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Regular expressions that help define the format of user entered content:
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_RE2 = re.compile(r"^.{3,20}$")
# This requires email to be a minimum of a@aaa (if that makes sense.):
USER_RE3 = re.compile("^[\S]+@[\S]+.[\S]+$")

# The next 7 functions validate the user entered content on the signup page:
def valid_username(username):
    if USER_RE.match(username):
        return username

def valid_password(password):
    if USER_RE2.match(password):
        return password

def valid_verify(verify, password):
    if (verify == password):
        return verify

# The next 3 functions give the option of validating firstname, lastname, and organization with regex (regex TBD):
def valid_firstname(firstname):
    if firstname:
        return firstname

def valid_lastname(lastname):
    if lastname:
        return lastname

def valid_organization(organization):
    if organization:
        return organization

def valid_email(email):
    if USER_RE3.match(email):
        return email

# These 3 functions and SECRET are for hashing and authenticating cookies:
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val

##### Where do I put this for real?:
# SECRET = 'imsosecret'

# These 3 functions are for hashing and salting passwords and authentication:
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(20))

# Should this be generated with hmac or bcrypt instead of sha256?:
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(name, pw, salt)

# Database interface:
class Users(db.Model):

    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    salt = db.StringProperty(required = True)
    firstname = db.StringProperty(required = True)
    lastname = db.StringProperty(required = True)
    organization = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class SignupPage(Handler):

    def get(self):

        # I guess a logged in user should be able to go to the signup page without being logged out. So maybe Set-Cookie only happens in the post method:
        self.render("ORHRAT_user_signup.html")

    def post(self):
        entered_username = self.request.get('username')
        entered_password = self.request.get('password')
        entered_verify = self.request.get('verify')
        entered_firstname = self.request.get('firstname')
        entered_lastname = self.request.get('lastname')
        entered_organization = self.request.get('organization')
        entered_email = self.request.get('email')

        # I've included firstname, lastname, and organization in the validation process to make it easier to add that functionality later, though there no actual validation implemented for those fields currently:
        username = valid_username(entered_username)
        password = valid_password(entered_password)
        verify = valid_verify(entered_verify, entered_password)
        firstname = valid_firstname(entered_firstname)
        lastname = valid_lastname(entered_lastname)
        organization = valid_organization(entered_organization)
        email = valid_email(entered_email)

        # Check if the username is taken.
        ##### Why can't I search db for key_name?
        username_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1", username)
        username_taken = username_check.get()

        # Initialize the error variable and excecute the if statements:
        username_error = ""
        if username_taken:
            username_error = "That username is taken."
        password_error = ""
        verify_error = ""
        firstname_error = ""
        lastname_error = ""
        organization_error = ""
        email_error = ""

        if not (username):
            username_error = "That's not a valid username."

        if not (password):
            password_error = "That isn't a valid password."

        if password:

            if not (verify):
                verify_error = "Your passwords didn't match."

        if not (firstname):
            firstname_error = "First name is required."

        if not (lastname):
            lastname_error = "Last name is required."

        if not (organization):
            organization_error = "Please enter your organization."

        if not (email):
            email_error = "That's not a valid email."

        # If user data is faulty, display error message(s):
        if not (username and password and verify and firstname and lastname and organization and email):
            self.render("ORHRAT_user_signup.html", username=entered_username, username_error=username_error, password=entered_password, password_error=password_error, verify=entered_verify, verify_error=verify_error, firstname=entered_firstname, firstname_error=firstname_error, lastname=entered_lastname, lastname_error=lastname_error, organization=entered_organization, organization_error=organization_error, email=entered_email, email_error=email_error)

        # Display "username taken" error:
        else:
            if username_taken:
                self.render("ORHRAT_user_signup.html", username=username, username_error=username_error, password=password, password_error=password_error, verify=verify, verify_error=verify_error, firstname=firstname, firstname_error=firstname_error, lastname=lastname, lastname_error=lastname_error, organization=organization, organization_error=organization_error, email=email, email_error=email_error)

            # If the user enters data properly:
            else:
                # Hash the password:
                h = make_pw_hash(username, password, salt = None)
                hashed_pw = h.split('|')[0]
                salt = h.split('|')[1]

                 # Enter valid data into database:
                users = Users(key_name=username, username=username, password=hashed_pw, salt=salt, firstname=firstname, lastname=lastname, organization=organization, email=email)
                users.put()

                # Hash cookie:
                un_cookie_val = make_secure_val(str(username))

                # Set Cookies:
                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % un_cookie_val)
                self.response.headers.add_header('Set-Cookie', 'st4a_score=; Path=/')

                self.redirect("/CAS.html")

class SkillsAssessment(db.Model):
    question = db.StringProperty(required = True)
    cboxstate = db.BooleanProperty(required = True)
    standard = db.StringProperty(required = True)
    username = db.StringProperty(required = True)

questions = ['st4_first', 'st4_second', 'st4_third', 'st4_fourth', 'st4_fifth', 'st4_sixth', 'st4_seventh', 'st4_eighth', 'st4_ninth', 'st4_tenth', 'st4_eleventh', 'st4_twelth', 'st4_thirteenth', 'st4_fourteenth', 'st4_fifteenth', 'st4_sixteenth', 'st4_seventeenth', 'st4_eighteenth', 'st4_ninteenth', 'st4_twentieth', 'st4_twenty_first']

# Computes the score:
def get_score(cbox_count):
    score = ""
    if cbox_count == 0:
        return 0
    elif cbox_count > 0 and cbox_count < 8:
        return 1
    elif cbox_count > 7 and cbox_count < 14:
        return 2
    elif cbox_count > 13 and cbox_count < 21:
        return 3
    elif cbox_count == 21:
        return 4

class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        # Get user input:
        un = self.request.get('username')
        pw = self.request.get('password')

        # Check that username is in database:
        username_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1", un)
        username_val = username_check.get()

        # If username is invalid, display error message, define login error and display:
        login_error = "Invalid login"
        if not username_val:
            self.render('login.html', login_error = login_error)

        # If username is valid, check password hash:
        if username_val:
            # Get the salt for the username from the database:
            get_salt = db.GqlQuery("SELECT salt FROM Users WHERE username = :1", un)
            got_salt = get_salt.get()
            s = got_salt.salt

            # Get the password hash for the username from database:
            password_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1", un)
            pwc = password_check.get()
            p = pwc.password

            # Make hash to check against database hash:
            pw_hash_salt = make_pw_hash(un, pw, s)
            pw_hash = pw_hash_salt.split('|')[0]

            # Check to see if newly created hash == database hash:
            if pw_hash != p:
                self.render('login.html', login_error=login_error)

            else:
                # Hash cookie:
                un_cookie_val = make_secure_val(str(un))

                # Get cbox_count so st4a_score can be calculated for cookie:
                cbox_count = 0
                for q in questions:
                    get_checkbox = db.GqlQuery("SELECT cboxstate FROM SkillsAssessment WHERE username = :1 and question = :2", un, q)
                    got_checkbox = get_checkbox.get()
                    if got_checkbox:
                        cbox = got_checkbox.cboxstate
                        print "cbox: " +str(cbox)
                        if cbox == True:
                            cbox_count += 1
                    else:
                        break
                score = str(get_score(cbox_count))

                # Create cookies:
                if got_checkbox == None:
                    self.response.headers.add_header('Set-Cookie', 'st4a_score=; Path=/')
                else:
                    self.response.headers.add_header('Set-Cookie', 'st4a_score=%s; Path=/' % score)

                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % un_cookie_val)
                self.redirect("/CAS.html")

class LoginMenuPage(Handler):
    def get(self):
        self.render("login-menu.html")

class IndexPage(Handler):
    def get(self):
        self.render("index.html")

class HealthyRelationshipsPage(Handler):
    def get(self):
        self.render("healthy_relationships.html")

class WhatIsMeantPage(Handler):
    def get(self):
        self.render("what_is_meant.html")

class ForgotPasswordPage(Handler):
    def get(self):
        self.render("forgot_password.html")

    def post(self):
        pass

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'st4a_score=; Path=/')
        self.redirect("/")

class CASPage(Handler):
    def get(self):
        un_hash = self.request.cookies.get('username')
        un = un_hash.split('|')[0]
        cookie = check_secure_val(un_hash)

        if cookie == None:
            self.response.headers.add_header('Set-Cookie', 'username =; Path=/')
            self.redirect("/")

        else:
            st4a_score = self.request.cookies.get('st4a_score')
            self.render("CAS.html", st4a_score=st4a_score)

# *** Why is it easier (more intuitive for me, at least) to have this outside the class that uses it?  How do I modify the function so it's stored inside the class? ... Come to think of it, if I have a class for every Standard, I need the function outside the class.
# Convert for HTML stynax:
def database_to_html(on_off):
    for i in range(len(on_off)):
        if on_off[i] == True:
            on_off[i] = "checked"
        elif on_off[i] == False:
            on_off[i] = ""
    return on_off

# Convert from HTML to GAE Datastore syntax:
def html_to_database(on_off):
    for i in range(len(on_off)):
        if on_off[i] == 'on':
            on_off[i] = True;
        elif on_off[i] == '':
            on_off[i] = False;
    return on_off

class Standard4Page(Handler):

    def get(self):

        un_hash = self.request.cookies.get('username')
        un = un_hash.split('|')[0]
        cookie = check_secure_val(un_hash)

        if cookie == None:
            self.response.headers.add_header('Set-Cookie', 'username =; Path=/')
            self.response.headers.add_header('Set-Cookie', 'st4a_score=; Path=/')
            self.redirect("/")

        # If there's a cookie for st4a_score, we'll need to get the cboxstate for each question from the database:
        elif cookie:
            st4a_score = self.request.cookies.get('st4a_score')

            # Get cboxstate from database, convert to HTML and pass back to standard_4 page:
            on_off = []
            checkbox_count = 0
            if st4a_score:
                for q in questions:
                    get_checkbox = db.GqlQuery("SELECT cboxstate FROM SkillsAssessment WHERE username = :1 and question = :2", un, q)
                    got_checkbox = get_checkbox.get()
                    cbox = got_checkbox.cboxstate
                    on_off.append(cbox)
                    if cbox == True:
                        checkbox_count += 1
            if not st4a_score and checkbox_count == 0:
                cbox_count = ""
            else:
                cbox_count = checkbox_count

            on_off = database_to_html(on_off)

            checkboxes = dict(zip(questions, on_off))

            self.render("standard_4.html", score=st4a_score, cbox_count=cbox_count, **checkboxes)

    def post(self):
        # Get username from cookie, authenticate, and reset, if it's invalid:
        un_hash = self.request.cookies.get('username')
        un = un_hash.split('|')[0]
        cookie = check_secure_val(un_hash)

        if cookie == None:
            self.response.headers.add_header('Set-Cookie', 'username = ; Path=/')
            self.redirect("/")

        elif cookie:
            on_off = []
            key_names = []
            for i in range(0, len(questions)):
                key_names.append(un + "_" + questions[i])

            # Get current checkbox states:
            cbox_count = 0
            for question in questions:
                q = self.request.get(question)
                if q == 'on':
                    cbox_count += 1
                on_off.append(q)

            score = str(get_score(cbox_count))

            # Convert from HTML to GAE Datastore syntax:
            html_to_database(on_off)

            # Add to database:
            for i in range(len(questions)):
                SA = SkillsAssessment(key_name=key_names[i], question=questions[i], cboxstate=on_off[i], standard="standard4",username=un,)
                SA.put()

            # Convert from GAE Datastore syntax to HTML:
            on_off = database_to_html(on_off)
            checkboxes = dict(zip(questions, on_off))

            self.response.headers.add_header('Set-Cookie', 'st4a_score=%s; Path=/' % score)

            # Render form with user's checkbox states preserved:
            self.render("standard_4.html", score=score, cbox_count=cbox_count, **checkboxes)

# GAE interface:
app = webapp2.WSGIApplication([('/', IndexPage), ('/login', LoginPage), ('/logout', LogoutPage), ('/index.html', IndexPage), ('/login.html', LoginPage), ('/login-menu.html', LoginMenuPage), ('/healthy_relationships.html', HealthyRelationshipsPage), ('/what_is_meant.html', WhatIsMeantPage), ('/ORHRAT_user_signup.html', SignupPage), ('/CAS.html', CASPage), ('/CAS', CASPage), ('/standard_4.html', Standard4Page), ('/forgot_password.html', ForgotPasswordPage)], debug=True)