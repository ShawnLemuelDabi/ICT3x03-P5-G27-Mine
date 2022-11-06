import pytest

from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options

import random

URL = "http://localhost:5001"
CORRECT_EMAIL = ("test" + str(random.randint(100000, 999999)) + "@gmail.com")


@pytest.fixture
def browser():
	# Set Firefox to run headless
	options = Options()
	options.headless = True

	# Initialize FirefoxDriver
	driver = Firefox(options = options)

	# Wait implicitly for elements to be ready before attempting interactions
	driver.implicitly_wait(10)

	# Return the driver object at the end of setup
	yield driver

	# For cleanup, quit the driver
	driver.quit()
