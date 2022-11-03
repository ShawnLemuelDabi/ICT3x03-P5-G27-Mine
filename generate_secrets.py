from secrets import choice
import string
import os

"""
Your SMTP settings
"""
SMTP_SERVER_HOST = "a"
SMTP_SERVER_PORT = "b"
SMTP_USE_TLS = False
SMTP_USE_SSL = True
SMTP_USERNAME = "c"
SMTP_PASSWORD = "d"

"""
Your Google reCAPTCHAv3 settings
"""
RC_SITE_KEY_V3 = "e"
RC_SECRET_KEY_V3 = "f"

"""
Your RSA key-pair location to sign the JWT tokens
"""
PRIVATE_KEY_FULL_PATH = "priv.key"
PUBLIC_KEY_FULL_PATH = "pub.key"

"""
Fill these up ONLY if you want to use your own keys.
Or if you don't want to rebuild your images again
(as running this script will overwrite our .env files)
"""
FLASK_LOGIN_SECRET = ""
RESET_PASSWORD_JWT_KEY = ""

MYSQL_USER = ""
MYSQL_PASSWORD = ""
MYSQL_ROOT_PASSWORD = ""

"""
DO NOT CHANGE ANYTHING PAST THIS LINE
"""

ALPHANUMERIC_SET = [string.ascii_letters, string.digits]
SECRET_LENGTH = 64

MYSQL_HOST = "db"
MYSQL_PORT = 3306


def verify_rsa_key_pairs_exists() -> None:
    """
    Tries to open and read the RSA public and private key.
    """
    try:
        open(PRIVATE_KEY_FULL_PATH, "r").read()
        open(PUBLIC_KEY_FULL_PATH, "r").read()
    except Exception as e:
        exit(f"I guess your public/private key either doesn't exists or cannot be read. {e}")


def generate_secrets(character_space: list[str], length: int) -> str:
    return "".join([choice("".join(character_space)) for i in range(length)])


def check_for_empty_settings() -> bool:
    str_variables_to_check = [
        SMTP_SERVER_HOST,
        SMTP_SERVER_PORT,
        SMTP_USERNAME,
        SMTP_PASSWORD,
        RC_SITE_KEY_V3,
        RC_SECRET_KEY_V3,
        PRIVATE_KEY_FULL_PATH,
        PUBLIC_KEY_FULL_PATH
    ]

    return all([type(i) == bool for i in [SMTP_USE_TLS, SMTP_USE_SSL]]) and all([i != "" for i in str_variables_to_check])


def dirty_get_class_attributes(obj: object) -> list[str]:
    return [i for i in dir(obj) if not i.startswith('_')]


def write_setting(key: any, val: str) -> str:
    return key + "=" + str(val).lower() + "\n"


class FlaskEnv:
    output_relative_path = "flasks/flask.env"

    flask_debug = 0
    flask_app = "./app.py"
    flask_run_port = "5000"
    flask_login_secret = FLASK_LOGIN_SECRET or generate_secrets(ALPHANUMERIC_SET, SECRET_LENGTH)

    smtp_server_host = SMTP_SERVER_HOST
    smtp_server_port = SMTP_SERVER_PORT
    smtp_use_tls = SMTP_USE_TLS
    smtp_use_ssl = SMTP_USE_SSL
    smtp_username = SMTP_USERNAME
    smtp_password = SMTP_PASSWORD

    reset_password_jwt_key = RESET_PASSWORD_JWT_KEY or generate_secrets(ALPHANUMERIC_SET, SECRET_LENGTH)

    mysql_host = MYSQL_HOST
    mysql_port = MYSQL_PORT

    rc_site_key_v3 = RC_SITE_KEY_V3
    rc_secret_key_v3 = RC_SECRET_KEY_V3

    @staticmethod
    def get_private_key() -> str:
        return open(PRIVATE_KEY_FULL_PATH, "r").read()

    @staticmethod
    def get_public_key() -> str:
        return open(PUBLIC_KEY_FULL_PATH, "r").read()


class MySQLEnv:
    output_relative_path = "flasks/mysql.env"

    mysql_database = "ssd"
    mysql_user = MYSQL_USER or generate_secrets(string.ascii_lowercase, 16)
    mysql_password = MYSQL_PASSWORD or generate_secrets(ALPHANUMERIC_SET, 32)


class MySQLRootEnv:
    output_relative_path = "mariadb/mysql_root.env"

    mysql_root_password = MYSQL_ROOT_PASSWORD or generate_secrets(ALPHANUMERIC_SET, 32)


if __name__ == "__main__":

    if not check_for_empty_settings():
        exit("Please leave no variables empty. For boolean variables, only use True or False.")

    verify_rsa_key_pairs_exists()

    pwd = os.path.abspath(os.curdir)

    """
    Check if this script is executed at the repo base path.
    Very basic checks
    """

    expected_items = [
        "flasks",
        ".gitignore",
        "README.md",
        "generate_secrets.py",
        "docker-compose.yml",
        ".vscode",
        "Jenkinsfile",
    ]

    if not set(expected_items).issubset(set(os.listdir(pwd))):
        exit("Please execute this script at the root directory of the git repo")

    """
    Check if the folder `mariadb` has been created already
    """
    mariadb_path = os.path.join(pwd, "mariadb")

    if not os.path.isdir(mariadb_path):
        print(f"Path '{mariadb_path}' does not exists. Creating one for you")
        os.mkdir(mariadb_path)

    print("Writing .env files...")

    my_env = FlaskEnv(), MySQLEnv(), MySQLRootEnv()

    for i in my_env:
        file_buffer = ""

        object_attributes = {}

        if type(i) == FlaskEnv:
            file_buffer += write_setting("PRIVATE_KEY", i.get_private_key())
            file_buffer += write_setting("PUBLIC_KEY", i.get_public_key())

        for j in dirty_get_class_attributes(i):
            if j != "output_relative_path":
                file_buffer += write_setting(j.upper(), i. __getattribute__(j))

        write_path = os.path.join(pwd, i. __getattribute__("output_relative_path"))

        with open(write_path, "w") as f:
            f.write(file_buffer)
            f.close()

    print("All done!")
    print("Please continue with the steps as described in README.md")
