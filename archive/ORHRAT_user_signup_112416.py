import webapp2
import re
import random
import string
import hashlib
import os
import jinja2
import hmac
from google.appengine.ext import db

# Set up the Jinja2 template filesystem:
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

# Regular expressions that help define the format of user entered content:
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_RE2 = re.compile(r"^.{3,20}$")
# This requires email to be a minimum of a@aaa (if that makes sense.):
USER_RE3 = re.compile("^[\S]+@[\S]+.[\S]+$")

# These 7 functions validate the user entered content on the signup page:
def valid_username(username):
    if USER_RE.match(username):
        return username

def valid_password(password):
    if USER_RE2.match(password):
        return password

def valid_verify(verify, password):
    if (verify == password):
        return verify

# These functions give the option of validating firstname, lastname, and organization with regex (regex TBD):
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

# The expression *a means the function will take any number of arguments, while **kw means it will take any number of keyword arguments. Functionally, it doesn't matter what the trailing letters are, just what number of asterisks.
# Helper functions for using Jinja2 templates:
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# The form username="" is a keyword argument:
class SignupPage(Handler):

    def get(self):

        # Get the username cookie:
        cookie_username = self.request.cookies.get('username')

        # Using the username-hash to verify, check that the username has not been tampered with:
        cookie_val = ''
        if cookie_username:
            cookie_val = check_secure_val(cookie_username)

            # If username cookie verifies properly, keep the cookie and display the signup form:
            if cookie_val:
                self.render("ORHRAT_user_signup.html")

            # Reset the cookie:
            elif cookie_val == None:
                self.response.headers.add_header('Set-Cookie', 'username =; Path=/')
                self.render("ORHRAT_user_signup.html")

        else:
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
        # Why can't I search db for key_name?
        username_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1", username)
        uc = username_check.get()

        # Initialize the error variable and excecute the if statements:
        username_error = ""
        if uc:
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
            password_error = "That wasn't a valid password."

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

        # If the user enters data properly:
        if (username and password and verify and firstname and lastname and organization and email):
            un = self.request.get('username')
            pw = self.request.get('password')
            fn = self.request.get('firstname')
            ln = self.request.get('lastname')
            o =  self.request.get('organization')
            e = self.request.get('email')

            # Hash the password:
            h = make_pw_hash(un, pw, salt = None)
            hashed_pw = h.split('|')[0]
            salt = h.split('|')[1]

            # Enter valid data into database:
            if not uc:
                users = Users(key_name=un, username=un, password=hashed_pw, salt=salt, firstname=firstname, lastname=lastname, organization=organization, email=email)
                users.put()

                # Hash cookie:
                un_cookie_val = make_secure_val(str(un))

                # Set Cookies:
                # self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % un_cookie_val)

                self.response.headers.add_header('Set-Cookie', 'cbox_bool=; Path=/')

                self.response.headers.add_header('Set-Cookie', 'st4a_score=; Path=/')

                self.redirect("/CAS.html")

            # Display "username taken" error:
            else:
                username_error = "That username is taken."
                self.render("ORHRAT_user_signup.html", username=username, username_error=username_error, password=password, password_error=password_error, verify=verify, verify_error=verify_error, firstname=firstname, firstname_error=firstname_error, lastname=lastname, lastname_error=lastname_error, organization=organization, organization_error=organization_error, email=email, email_error=email_error)

# If user data is faulty, display error message(s):
        else:
            self.render("ORHRAT_user_signup.html", username=entered_username, username_error=username_error, password=entered_password, password_error=password_error, verify=entered_verify, verify_error=verify_error, firstname=entered_firstname, firstname_error=firstname_error, lastname=entered_lastname, lastname_error=lastname_error, organization=entered_organization, organization_error=organization_error, email=entered_email, email_error=email_error)

# Originally thought these functions should be housed in a class, but I'm starting to think there's no benefit to that. It's just the desire for clean and ordered code.
# These 3 functions and SECRET are for hashing and authenticating cookies:
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val

# Where do I put this for real?:
SECRET = 'imsosecret'

# These 3 functions are for hashing and salting passwords and authentication:
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

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

class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        # Get user input:
        un = self.request.get('username')
        pw = self.request.get('password')

        # Define login error:
        login_error = "Invalid login"

        # Check that username is in database:
        username_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1", un)
        uc = username_check.get()

        # If username is invalid, display error message:
        if not uc:
            self.render('login.html', login_error = login_error)

        # If username is valid, check password hash:
        if uc:
            # Get the salt associated with the username:
            get_salt = db.GqlQuery("SELECT salt FROM Users WHERE username = :1", un)
            got_salt = get_salt.get()
            s = got_salt.salt

            # Get hash from database:
            password_check = db.GqlQuery("SELECT * FROM Users WHERE username = :1", un)
            pwc = password_check.get()
            p = pwc.password

            # Make hash to check against database hash:
            pw_hash_salt = make_pw_hash(un, pw, s)
            pw_hash = pw_hash_salt.split('|')[0]

            # Check to see if newly created hash == database hash:
            if pw_hash != p:
                self.render('login.html', login_error = login_error)

            else:
                # Hash cookie:
                un_cookie_val = make_secure_val(str(un))

                # Set cookies and redirect to '/CAS.html':
                # Get cbox_count:
                get_checkboxes = db.GqlQuery("SELECT cboxstate FROM SkillsAssessment WHERE username = :1", un)
                got_checkboxes = get_checkboxes.get()
                # print "got_checkboxes:" + str(got_checkboxes)
                if got_checkboxes == None:
                    self.response.headers.add_header('Set-Cookie', 'cbox_bool=; Path=/')
                else:
                    self.response.headers.add_header('Set-Cookie', 'cbox_bool=1; Path=/')

                self.response.headers.add_header('Set-Cookie', 'st4_score=%s; Path=/' % **************)

                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % un_cookie_val)
                self.redirect("/CAS.html")







# This shows the long version of authenticating cookies.
# Not using the /welcome page for now.
class WelcomePage(Handler):
    def get(self):
        name_hash = self.request.cookies.get('username')
        name = name_hash.split('|')[0]

        cookie_val = check_secure_val(name_hash)
        if cookie_val == None:
            self.response.headers.add_header('Set-Cookie', 'username =; Path=/')
            self.redirect("/")

        else:
            self.render("CAS.html")
            # self.response.out.write("Welcome, %s" %name)

# This function authenticates the cookie.
# Not sure how to get it working:
# def check_cookie():
#     pass
# def reset_cookie():
#     print "reset cookie"
#     return self.response.headers.add_header('Set-Cookie', 'username = Path=/')
#     self.redirect("/")

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

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'cbox_bool=; Path=/')
        self.response.headers.add_header('Set-Cookie', 'st4a_score=; Path=/')
        self.render("ORHRAT_user_signup.html")

class CASPage(Handler):
    def get(self):
        # I don't think it's necessary to authenticate the cookie here:
        un = self.request.cookies.get('username')
        cc = check_secure_val(un)

        if cc == None:
            self.response.headers.add_header('Set-Cookie', 'username = Path=/')
            self.redirect("/")

        cbox_bool = self.request.cookies.get('cbox_bool')
        print 'cbox_bool: ' + str(cbox_bool)
        if cbox_bool == 1:
            pass

        st4a_score = self.request.cookies.get('st4a_score')
        print 'st4a_score: ' + str(st4a_score)
        if st4a_score == 1:
            pass

        self.render("CAS.html")

class Standard4Page(Handler):
    def get(self):

        un_hash = self.request.cookies.get('username')
        cc = check_secure_val(un_hash)

        if cc == None:
            self.response.headers.add_header('Set-Cookie', 'username = Path=/')
            self.redirect("/")

        # Now I need to check if theres cboxstate in the database and load it if there is:

        # else:
        #     you_marked_number = self.request.get('you-marked-number')
        #     print "you_marked_number: " + you_marked_number
        #     if you_marked_number == "":
        #         self.response.headers.add_header('Set-Cookie', 'st4a_r_and_e = display:none; Path=/')
            # elif cbox_count != "":
            #     self.response.headers.add_header('Set-Cookie', 'st4a_r_and_e = display:inline; Path=/')
        self.render("standard_4.html")

    def post(self):

        # 1. Is it better to start with a dictionary rather than 2 separate lists?
        #q_on_off = {'st4_first': "", 'st4_second': ""}

        # Get username from cookie, authenticate, and reset, if it's invalid:
        un_hash = self.request.cookies.get('username')
        un = un_hash.split('|')[0]
        cc = check_secure_val(un_hash)
        if cc == None:
            self.response.headers.add_header('Set-Cookie', 'username = ; Path=/')
            self.redirect("/")
        else:
            # Look into name="st4" for all checkboxes in HTML.
            questions = ['st4_first', 'st4_second', 'st4_third', 'st4_fourth', 'st4_fifth', 'st4_sixth', 'st4_seventh', 'st4_eighth', 'st4_ninth', 'st4_tenth', 'st4_eleventh', 'st4_twelth', 'st4_thirteenth', 'st4_fourteenth', 'st4_fifteenth', 'st4_sixteenth', 'st4_seventeenth', 'st4_eighteenth', 'st4_ninteenth', 'st4_twentieth', 'st4_twenty_first']

            on_off = []
            key_names = []
            for i in range(0, len(questions)):
                key_names.append(un + "_" + questions[i])

            # Look into get_all() to save to a list.
            # Get current checkbox states:
            cbox_count = 0
            for question in questions:
                q = self.request.get(question)
                if q == 'on':
                    cbox_count += 1
                on_off.append(q)

            # This could be a global function:
            score = ""
            if cbox_count == 0:
                score = 0
            elif cbox_count > 0 and cbox_count < 8:
                score = 1
            elif cbox_count > 7 and cbox_count < 14:
                score = 2
            elif cbox_count > 13 and cbox_count < 21:
                score = 3
            elif cbox_count == 21:
                score = 4

            # Convert for GAE Datastore syntax:
            for i in range(0, len(on_off)):
                if on_off[i] == 'on':
                    on_off[i] = True;
                elif on_off[i] == '':
                    on_off[i] = False;

            # Validate checkboxes?

            # Add to database:
            for i in range(len(questions)):
                SA = SkillsAssessment(key_name=key_names[i], cboxstate=on_off[i], standard="standard4",username=un,)
                SA.put()

            checked = [0] * len(on_off)

            # It might be better if this stuff were in the HTML.
            # Convert for HTML stynax:
            for i in range(len(on_off)):
                if on_off[i] == True:
                    checked[i] = "checked"
                elif on_off[i] == False:
                    checked[i] = ""
                q = questions[i]
                x = checked[i]

            checkboxes = dict(zip(questions, checked))

            # you_marked_number = self.request.get('you-marked-number')
            # print "you_marked_number: " + str(cbox_count)
            if cbox_count != "":
                self.response.headers.add_header('Set-Cookie', 'cbox_bool=1; Path=/')

            # str_score = str(score)
            print "score: " + str(score)
            # if str_score :
            self.response.headers.add_header('Set-Cookie', 'st4a_score=%s; Path=/' % str(score))

            # Render form with user's checkbox states preserved.
            # I need the checkThis function to reactivate when the page reloads:
            self.render("standard_4.html", score=score, cbox_count=cbox_count, **checkboxes)

class SkillsAssessment(db.Model):
    cboxstate = db.BooleanProperty(required = True)
    standard = db.StringProperty(required = True)
    username = db.StringProperty(required = True)

# GAE interface:
app = webapp2.WSGIApplication([('/', SignupPage), ('/welcome', WelcomePage), ('/login', LoginPage), ('/logout', LogoutPage), ('/index.html', IndexPage), ('/login.html', LoginPage), ('/login-menu.html', LoginMenuPage), ('/healthy_relationships.html', HealthyRelationshipsPage), ('/what_is_meant.html', WhatIsMeantPage), ('/ORHRAT_user_signup.html', SignupPage), ('/CAS.html', CASPage), ('/standard_4.html', Standard4Page), ('/forgot_password.html', ForgotPasswordPage)], debug=True)