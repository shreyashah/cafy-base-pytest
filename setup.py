'''
Created on Feb 16, 2017

@author: fahad naeem khan
'''
# sample ./setup.py file
from setuptools import setup


setup(
    name="pytest_cafy",
    packages=['pytest_cafy'],
    package_data={'pytest_cafy': ['resources/*']},
    author='Fahad Naeem Khan',
    author_email='fahadnaeemkhan@gmail.com',
    install_requires=['pytest>=2.3', 'jinja2'],
    # the following makes a plugin available to pytest
    entry_points={
        'pytest11': ['pytest_cafy = pytest_cafy.plugin']
    },
    # custom PyPI classifier for pytest plugins
    classifiers=[
        "Framework :: Pytest",
    ],
)
