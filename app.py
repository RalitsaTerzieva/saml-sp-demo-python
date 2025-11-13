import os
from flask import Flask, request, redirect, make_response, render_template_string, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

def prepare_flask_request(req):
    # OneLogin toolkit expects this format
    return {
        'https': 'on' if req.environ.get('wsgi.url_scheme') == 'https' else 'off',
        'http_host': req.host,
        'server_port': req.environ.get('SERVER_PORT'),
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy()
    }

@app.route('/')
def index():
    return render_template_string("""
      <h2>SAML SP Demo</h2>
      <a href="{{ url_for('saml_login') }}">Login with SAML IdP</a>
    """)

@app.route('/sso/login')
def saml_login():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))
    return redirect(auth.login())

@app.route('/sso/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        return f"Auth error: {errors}", 400
    nameid = auth.get_nameid()
    attributes = auth.get_attributes()
    return render_template_string("<h3>Logged in as {{name}}</h3><pre>{{attrs}}</pre>",
                                  name=nameid, attrs=attributes)

@app.route('/sso/metadata')
def metadata():
    # return SP metadata so the IdP can be configured
    from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
    settings = OneLogin_Saml2_Auth(prepare_flask_request(request), custom_base_path=os.path.join(os.getcwd(), 'saml')).get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if len(errors) > 0:
        return f"Metadata errors: {errors}", 500
    resp = make_response(metadata, 200)
    resp.headers['Content-Type'] = 'text/xml'
    return resp

if __name__ == "__main__":
    app.run(port=int(os.getenv("PORT", 5000)), debug=True)
