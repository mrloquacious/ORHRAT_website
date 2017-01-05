import webapp2
import cgi
import re
import os

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_RE2 = re.compile(r"^.{3,20}$")
USER_RE3 = re.compile("^[\S]+@[\S]+.[\S]+$")

# In case I want to validate other parameters with a regex:
#USER_RE4 = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

def escape_html(s):
    return cgi.escape(s, quote = True)

def valid_username(username):
    if username:
        return USER_RE.match(username)

def valid_password(password):
    if password:
        return USER_RE2.match(password)

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

    elif email:
        return USER_RE3.match(email)

# form="""
# <html>
#     <body>
#         <h2>Signup</h2>
#         <form method="post">
#             <table>
#                 <tbody>
#                     <tr>
#                         <td style="text-align:right">Username <input type="text" name= "username" value="%(username)s"></td><td style="color: red">%(username_error)s</td>
#                     </tr>
#                     <tr>
#                         <td style="text-align:right">Password <input type="password" name= "password" value="%(password)s"></td><td style="color: red">%(password_error)s</td>
#                     </tr>
#                     <tr>
#                         <td style="text-align:right">Verify Password <input type="password" name= "verify" value="%(verify)s"></td><td style="color: red">%(verify_error)s</td>
#                     </tr>
#                     <tr>
#                         <td style="text-align:right">First Name <input type="text" name= "firstname" value="%(firstname)s"></td><td style="color: red">%(firstname_error)s</td>
#                     </tr>
#                     <tr>
#                         <td style="text-align:right">Last Name <input type="text" name= "lastname" value="%(lastname)s"></td><td style="color: red">%(lastname_error)s</td>
#                     </tr>
#                     <tr>
#                         <td style="text-align:right">Organization <input type="text" name= "organization" value="%(organization)s"></td><td style="color: red">%(organization_error)s</td>
#                     </tr>
#                         <td style="text-align:right">Email (optional) <input type="text" name= "email" value="%(email)s"></td><td style="color: red">%(email_error)s</td>
#                     </tr>
#                 </tbody>
#             </table>
#             <input type="submit">
#         </form>
#     </body>
# </html>
# """

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# The expression *a means the function will take any number of arguments, while **kw means it will take any number of keyword arguments:
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

# The form username="" is a keyword argument:
class MainPage(Handler):
    def write_form(self, username="", username_error="", password="", password_error="", verify="", verify_error="", firstname="", firstname_error="", lastname="", lastname_error="", organization="", organization_error="",email="", email_error=""):
        self.response.out.write(form % {"username": escape_html(                                username),
                                        "username_error": username_error,
                                        "password": escape_html(password),
                                        "password_error": password_error,
                                        "verify": escape_html(verify),
                                        "verify_error": verify_error,
                                        "firstname": escape_html(firstname),
                                        "firstname_error": firstname_error,
                                        "lastname": escape_html(lastname),
                                        "lastname_error": lastname_error,
                                        "organization": escape_html(organization),
                                        "organization_error": organization_error,
                                        "email": escape_html(email),
                                        "email_error": email_error})
    def get(self):
        self.write_form()
        #self.render("ORHRAT_user_signup.html")

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
            firstname_error = "No."

        if not (lastname):
            lastname_error = "Nope."

        if not (organization):
            organization_error = "Uh uh."

        if not (email):
            email_error = "That's not a valid email."

        if (username and password and verify and firstname and lastname and organization and email):


            un = self.request.get('username')
            # Write to database.
            self.redirect("/welcome?username="+un)

        else:
            self.write_form(entered_username, username_error, entered_password, password_error, entered_verify, verify_error, entered_firstname, firstname_error, entered_lastname, lastname_error, entered_organization, organization_error, entered_email, email_error)

class Users(db.Model):

    #ID = db. autocreated serial int
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    firstname = db.StringProperty(required = True)
    lastname = db.StringProperty(required = True)
    organization = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class WelcomePage(webapp2.RequestHandler):
    def get(self):
        name = self.request.get('username')

        self.response.out.write("Welcome, %s" %name)

app = webapp2.WSGIApplication([('/', MainPage), ('/welcome', WelcomePage)], debug=True)