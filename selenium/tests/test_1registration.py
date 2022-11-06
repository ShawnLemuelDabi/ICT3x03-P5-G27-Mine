import pytest

from initialization import browser, URL, CORRECT_EMAIL

from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException

import os

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
	Reset the db before running this test

	Checks if the registration page returns the correct response page

	Allowed email --> Return register success
	Not Allowed email / Not an email --> Does not return register success
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

			assert 1 == 1

		except NoSuchElementException:
			pytest.fail()
		
	else:
		try:
			browser.find_element("id", "token")

		except NoSuchElementException:
			assert 1 == 1

@pytest.mark.dependency(name='registration_fields_are_validated', depends=['registration_respond_correctly'])
def test_registration_fields_are_validated(browser):
	"""
	* Requires the previous test to be successful
	- First Name
	- Last Name
	- Password
	- Confirm Password (Must be the same as the password field)
	- Phone Number
	- License Picture
	"""

	browser.get(URL + PAGENAME + "/" + TOKEN)

	firstname_input = browser.find_element("id", "first_name")
	firstname_input.send_keys("firstname")

	lastname_input = browser.find_element("id", "last_name")
	lastname_input.send_keys("lastname")

	pw_input = browser.find_element("id", "password")
	pw_input.send_keys("P@ssw0rd")

	cwd_input = browser.find_element("id", "confirm_password")
	cwd_input.send_keys("P@ssw0rd")

	phone_input = browser.find_element("id", "phone_number")
	phone_input.send_keys("87654321")

	license_filepath = os.path.join(os.getcwd(), "license_test.jpeg")
	license_input = browser.find_element("id", "license")
	license_input.send_keys(license_filepath)

	firstname_input.send_keys(Keys.RETURN)

	assert browser.find_element("id", "success")
