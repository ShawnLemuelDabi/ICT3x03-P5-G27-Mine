import pytest

from selenium import webdriver
from selenium.webdriver import Firefox
from selenium.webdriver.firefox.options import Options

import random

URL = "http://flasks:5000"
CORRECT_EMAIL = ("test" + str(random.randint(100000, 999999)) + "@gmail.com")


@pytest.fixture
def browser():
	# Set Firefox to run headless
	options = Options()
	options.add_argument("--disable-blink-features=AutomationControlled")
	options.headless = True

	# Initialize FirefoxDriver
	# driver = Firefox(options = options)
	driver = webdriver.Remote(
        command_executor="http://selenium-worker:4444",
        options=options
    )

	# Wait implicitly for elements to be ready before attempting interactions
	driver.implicitly_wait(10)

	# Return the driver object at the end of setup
	yield driver

	# For cleanup, quit the driver
	driver.quit()
