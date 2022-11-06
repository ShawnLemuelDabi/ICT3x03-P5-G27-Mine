import pytest

from initialization import browser, URL, CORRECT_EMAIL

from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException

PAGENAME = "/login"

@pytest.mark.parametrize(
    "emailtotest, passwordtotest, result", [
		("failemail", "failpassword", False),
		(CORRECT_EMAIL, "complexP@ssw0rd12345", True),
    ]
)
@pytest.mark.dependency(name='login_page_respond_correctly')
# @pytest.mark.depends(on=['test_1registration.py::registration_respond_correctly'])
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
			assert True
		
		except NoSuchElementException:
			pytest.fail()

	else:
		try:
			browser.find_element("id", "logout")
			pytest.fail()
		
		except NoSuchElementException:
			assert True



# def test_otp_function(browser):
# 	"""
# 	Valid OTP -->
# 	Invalid OTP -->
# 	"""
