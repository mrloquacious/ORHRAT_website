import webapp2
import re
import random
import string
import hashlib
import os
import jinja2
import hmac
from google.appengine.ext import db

# Pretty sure I can get rid of this since the template autoescape = True:
import cgi

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_RE2 = re.compile(r"^.{3,20}$")

# This requires email to be a minimum of a@aaa (if that makes sense.):
USER_RE3 = re.compile("^[\S]+@[\S]+.[\S]+$")

# In case I want to validate other parameters with a regex:
#USER_RE4 = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

# Pretty sure I can get rid of this as the template autoescape = True:
def escape_html(s):
    return cgi.escape(s, quote = True)

def valid_username(username):
    if USER_RE.match(username):
        return username

def valid_password(password):
    if USER_RE2.match(password):
        return password

def valid_verify(verify, password):
    if (verify == password):
        return verify

# These functions give the option of validating firstname, lastname, and organization with regex.
def valid_firstname(firstname):
    if firstname:
        return firstname
        #return USER_RE4.match(firstname)
def valid_lastname(lastname):
    if lastname:
        return lastname
        #return USER_RE4.match(lastname)
def valid_organization(organization):
    if organization:
        return organization
        #return USER_RE4.match(organization)

def valid_email(email):
    if not (email):
        return " "

    elif USER_RE3.match(email):
        return email

# The expression *a means the function will take any number of arguments, while **kw means it will take any number of keyword arguments:
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# The form username="" is a keyword argument:
class MainPage(Handler):

    def get(self):
        self.render("ORHRAT_user_signup.html")

    def post(self):
        entered_username = self.request.get('username')
        #print "entered_username: " + entered_username
        entered_password = self.request.get('password')
        entered_verify = self.request.get('verify')
        entered_firstname = self.request.get('firstname')
        #print "entered_firstname: " + entered_firstname
        entered_lastname = self.request.get('lastname')
        entered_organization = self.request.get('organization')
        entered_email = self.request.get('email')

# I've included firstname, lastname, and organization in the validation process to make it easier to add that functionality later, though there no actual validation implemented for those fields currently:
        username = valid_username(entered_username)
        #print "username: " + str(username)
        password = valid_password(entered_password)
        verify = valid_verify(entered_verify, entered_password)
        firstname = valid_firstname(entered_firstname)
        #print "firstname: " + str(firstname)
        lastname = valid_lastname(entered_lastname)
        organization = valid_organization(entered_organization)
        email = valid_email(entered_email)

        username_error = ""
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

        if (username and password and verify and firstname and lastname and organization and email):

            # Write to database:
            users = Users(username=username, password=password, verify=verify, firstname=firstname, lastname=lastname, organization=organization, email=email)
            users.put()

            un = self.request.get('username')
            self.redirect("/welcome?username="+un)

        else:
            self.render("ORHRAT_user_signup.html", username=entered_username, username_error=username_error, password=entered_password, password_error=password_error, verify=entered_verify, verify_error=verify_error, firstname=entered_firstname, firstname_error=firstname_error, lastname=entered_lastname, lastname_error=lastname_error, organization=entered_organization, organization_error=organization_error, email=entered_email, email_error=email_error)

class Users(db.Model):

# Might not need to create ID (an ID is autocreated in AE Datastore):
    #ID = db. autogenerated serial int
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    firstname = db.StringProperty(required = True)
    lastname = db.StringProperty(required = True)
    organization = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)

class WelcomePage(webapp2.RequestHandler):
    def get(self):
        name = self.request.get('username')

        self.response.out.write("Welcome, %s" %name)

app = webapp2.WSGIApplication([('/', MainPage), ('/welcome', WelcomePage)], debug=True)