import pytest

from initialization import browser, URL, CORRECT_EMAIL

from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException

PAGENAME = "/login"

@pytest.mark.parametrize(
    "emailtotest, passwordtotest, result", [
		("failemail", "failpassword", False),
		(CORRECT_EMAIL, "P@ssw0rd", True),
    ]
)
@pytest.mark.dependency(name='login_page_respond_correctly', depends=['test_registration.py::registration_fields_are_validated'])
@pytest.mark.run(after="test_registration.py::registration_fields_are_validated")
def test_login_page_respond_correctly(browser, emailtotest, passwordtotest, result):
	"""
	Need to ensure that the registration is successful first
	"""

	browser.get(URL + PAGENAME)

	email_input = browser.find_element("id", "email")
	email_input.send_keys(emailtotest)
    
	password_input = browser.find_element("id", "password")
	password_input.send_keys(passwordtotest)

	password_input.send_keys(Keys.RETURN)

	if result:
		try:
			browser.find_element("id", "logout")
			assert 1==1
		
		except NoSuchElementException:
			pytest.fail()

	else:
		try:
			browser.find_element("id", "logout")
			pytest.fail()
		
		except NoSuchElementException:
			assert 1==1



# def test_otp_function(browser):
# 	"""
# 	Valid OTP -->
# 	Invalid OTP -->
# 	"""
