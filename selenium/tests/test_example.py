import pytest

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By


@pytest.fixture
def browser():
    # Initialize FirefoxDriver
    driver = webdriver.Remote(
        command_executor="http://selenium-worker:4444",
        options=webdriver.FirefoxOptions()
    )

    # Wait implicitly for elements to be ready before attempting interactions
    driver.implicitly_wait(10)

    # Return the driver object at the end of setup
    yield driver

    # For cleanup, quit the driver
    driver.quit()


def test_example_login(browser):
    url = "http://flasks:5000/login"

    browser.get(url)

    search_input = browser.find_element(By.XPATH, "/html/body/div[1]/div/div/div[3]/div/form/div[1]/div[1]/div/div/input")
    search_input = search_input.send_keys("test@gmail.com" + Keys.TAB)

    search_input = browser.find_element(By.XPATH, "/html/body/div[1]/div/div/div[3]/div/form/div[1]/div[2]/div/div/input")
    search_input = search_input.send_keys("testpassword" + Keys.RETURN)

    browser.implicitly_wait(3)
    error_prompt = browser.find_element(By.XPATH, "/html/body/div[1]/div/div/div[2]/div")
    assert "Incorrect credentials" in error_prompt.text
