from flask import Flask 
from blueprints.index import index_blueprint
from blueprints.encrypt import encrypt_blueprint
from blueprints.decrypt import decrypt_blueprint
from blueprints.generate import generate_blueprint

app = Flask(__name__)

# Register all the blueprints
app.register_blueprint(index_blueprint)
app.register_blueprint(encrypt_blueprint)
app.register_blueprint(decrypt_blueprint)
app.register_blueprint(generate_blueprint)

# Run the app
if __name__ == '__main__':
    app.run()