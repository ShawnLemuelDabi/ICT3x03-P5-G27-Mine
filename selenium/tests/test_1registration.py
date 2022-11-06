import pytest

from initialization import browser, URL, CORRECT_EMAIL

from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException

import os

PAGENAME = "/register"

TESTING_DATA = {

	"firstname_fail" : {
		"firstname": "firstnamefail12345",
		"lastname": "lastnamepass",
		"password": "complexP@ssw0rd12345",
		"confirm_password": "complexP@ssw0rd12345",
		"phoneno": "87654321",
		"license": "license_test.jpeg",
		"error_message": "Never input validate first name"
	},

	"lastname_fail" : {
		"firstname": "firstnamepass",
		"lastname": "lastnamefail12345",
		"password": "complexP@ssw0rd12345",
		"confirm_password": "complexP@ssw0rd12345",
		"phoneno": "87654321",
		"license": "license_test.jpeg",
		"error_message": "Never input validate last name"
	},

	"password_fail" : {
		"firstname": "firstnamepass",
		"lastname": "lastnamepass",
		"password": "passwordfail",
		"confirm_password": "passwordfail",
		"phoneno": "87654321",
		"license": "license_test.jpeg",
		"error_message": "Never input validate password"
	},

	"confirm_password_fail" : {
		"firstname": "firstnamepass",
		"lastname": "lastnamepass",
		"password": "complexP@ssw0rd12345",
		"confirm_password": "complexP@ssw0rd123456789",
		"phoneno": "87654321",
		"license": "license_test.jpeg",
		"error_message": "Never check password matches"
	},

	"phonenumber_fail" : {
		"firstname": "firstnamepass",
		"lastname": "lastnamepass",
		"password": "complexP@ssw0rd12345",
		"confirm_password": "complexP@ssw0rd12345",
		"phoneno": "phonenumberfail",
		"license": "license_test.jpeg",
		"error_message": "Never input validate phone number"
	},

	"license_fail" : {
		"firstname": "firstnamepass",
		"lastname": "lastnamepass",
		"password": "complexP@ssw0rd12345",
		"confirm_password": "complexP@ssw0rd12345",
		"phoneno": "87654321",
		"license": "license_test.txt",
		"error_message": "Never check for file type of uploaded file"
	},

	"success" : {
		"firstname": "firstnamepass",
		"lastname": "lastnamepass",
		"password": "complexP@ssw0rd12345",
		"confirm_password": "complexP@ssw0rd12345",
		"phoneno": "87654321",
		"license": "license_test.jpeg",
		"error_message": "ERROR ERROR ERROR ERROR",
	},
}

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

	def send_input(browser, scenario):

		firstname_input = browser.find_element("id", "first_name")
		firstname_input.send_keys(TESTING_DATA[scenario]["firstname"])

		lastname_input = browser.find_element("id", "last_name")
		lastname_input.send_keys(TESTING_DATA[scenario]["lastname"])

		pw_input = browser.find_element("id", "password")
		pw_input.send_keys(TESTING_DATA[scenario]["password"])

		cwd_input = browser.find_element("id", "confirm_password")
		cwd_input.send_keys(TESTING_DATA[scenario]["confirm_password"])

		phone_input = browser.find_element("id", "phone_number")
		phone_input.send_keys(TESTING_DATA[scenario]["phoneno"])

		license_filepath = os.path.join(os.getcwd(), TESTING_DATA[scenario]["license"])
		license_input = browser.find_element("id", "license")
		license_input.send_keys(license_filepath)

		browser.find_element(By.XPATH, "/html/body/div[1]/div/div/div[2]/div/form/div/div[9]/div/input").submit()

		if scenario == "success":
			try:
				browser.find_element("id", "success")
				return

			except NoSuchElementException:
				return TESTING_DATA[scenario]["error_message"]
		
		else:
			try:
				browser.find_element("id", "success")
				return TESTING_DATA[scenario]["error_message"]

			except NoSuchElementException:
				return


	browser.get(URL + PAGENAME)

	email_input = browser.find_element("id", "email")
	email_input.send_keys(emailtotest)

	browser.find_element(By.XPATH, "/html/body/div[1]/div/div[2]/div/div[2]/div/form/div/div[3]/div/input").submit()

	if result:
		try:
			response = browser.find_element("id", "token")
			TOKEN = response.get_attribute("innerHTML")

			browser.get(URL + PAGENAME + "/" + TOKEN)

			error_messages = []

			for scenario in TESTING_DATA.keys():
				error_messages.append(send_input(browser, scenario))

			if error_messages.count(None) == len(error_messages):
				assert True

			else:
				assert False, ", ".join(error_messages)

		except NoSuchElementException:
			pytest.fail("Invalid email provided")
		
	else:
		try:
			browser.find_element("id", "token")
			pytest.fail("Funny situation")

		except NoSuchElementException:
			assert True
