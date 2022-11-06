import pytest

from initialization import browser, URL, CORRECT_EMAIL

from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException

import os, re

# Can remove the hardcoded regex if this works
# from flasks.input_validation import NAME_REGEX_PATTERN, \
# 									PHONE_NUMBER_REGEX_PATTERN, \
# 									PASSWORD_REGEX_PATTERN, \
# 									ALLOWED_FILETYPE

NAME_REGEX_PATTERN = r"^[^\s]+[A-Za-z ,.'-]{1,35}$"
PHONE_NUMBER_REGEX_PATTERN = r"^(8|9){1}[0-9]{7}$"
PASSWORD_REGEX_PATTERN = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
ALLOWED_FILETYPE = ["jpg", "jpeg", "png"]

PAGENAME = "/register"

@pytest.mark.parametrize(
    "emailtotest, result", [
		("notanemail", False),
		("notanemail@notemaildomain.sg", False),
		(CORRECT_EMAIL, True),
    ]
)
@pytest.mark.dependency(name='registration_respond_correctly')
def test_registration_respond_correctly(browser, emailtotest, result):
	"""
	Input validation in progress

	Checks if the registration page returns the correct response page

	Allowed email --> Return register success
	Not Allowed email / Not an email --> Does not return register success

	* Requires the previous test to be successful
	- First Name
	- Last Name
	- Password
	- Confirm Password (Must be the same as the password field)
	- Phone Number
	- License Picture
	"""

	browser.get(URL + PAGENAME)

	email_input = browser.find_element("id", "email")
	email_input.send_keys(emailtotest)

	email_input.send_keys(Keys.RETURN)

	if result:
		try:
			response = browser.find_element("id", "token")
			global TOKEN
			TOKEN = response.get_attribute("innerHTML")

			browser.get(URL + PAGENAME + "/" + TOKEN)

			firstname_input = browser.find_element("id", "first_name")
			firstname_input.send_keys("firstname")

			lastname_input = browser.find_element("id", "last_name")
			lastname_input.send_keys("lastname")

			pw_input = browser.find_element("id", "password")
			pw_input.send_keys("P@ssw0rd12345")

			cwd_input = browser.find_element("id", "confirm_password")
			cwd_input.send_keys("P@ssw0rd12345")

			phone_input = browser.find_element("id", "phone_number")
			phone_input.send_keys("87654321")

			license_filepath = os.path.join(os.getcwd(), "license_test.jpeg")
			license_input = browser.find_element("id", "license")
			license_input.send_keys(license_filepath)

			firstname_input.send_keys(Keys.RETURN)

			assert browser.find_element("id", "success")

		except NoSuchElementException:
			pytest.fail("Invalid email provided")
		
	else:
		try:
			browser.find_element("id", "token")
			pytest.fail("Funny situation")

		except NoSuchElementException:
			assert True
