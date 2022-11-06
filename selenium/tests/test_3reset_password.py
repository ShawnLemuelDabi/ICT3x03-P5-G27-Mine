import pytest

from initialization import browser, URL, CORRECT_EMAIL

from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException


PAGENAME = "/forgot_password"

@pytest.mark.parametrize(
	"emailtotest, result", [
		("notanemail", False),
		("notanemail@notemaildomain.sg", False),
		("notanactualuser@gmail.com", False),
		(CORRECT_EMAIL, True),
	]
)
@pytest.mark.dependency(name='reset_password_respond_correctly', depends=['test_registration.py::registration_fields_are_validated'])
@pytest.mark.run(after="test_registration.py::registration_fields_are_validated")
def test_reset_password_respond_correctly(browser, emailtotest, result):
	"""
	Checks if the reset password page returns the correct page
	"""

	browser.get(URL + PAGENAME)

	email_input = browser.find_element("id", "email")
	email_input.send_keys(emailtotest)

	email_input.send_keys(Keys.RETURN)

	if result:
		try:
			response = browser.find_element("id", "token")
			
			global token
			token = response.get_attribute("innerHTML")
	
			assert 1==1
		
		except NoSuchElementException:
			pytest.fail()

	else:
		try:
			browser.find_element("id", "token")
			pytest.fail()
		
		except NoSuchElementException:
			assert 1==1


# def test_verify_reset_page_respond_correcty(browser):
# 	"""
# 	Check password function
# 	"""

# 	browser.get(URL + "/verify_reset/" + token)

# 	assert browser.page_source == 0
