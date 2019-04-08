'''
Created on Feb 16, 2017

@author: ask-cafy@cisco.com
'''
# sample ./setup.py file
from setuptools import setup

from cafy_pytest.__version__ import __version__
#__version__ = "0.1.0"  

setup(
    name="cafy_pytest",
    packages=['cafy_pytest'],
    package_data={'cafy_pytest': ['resources/*']},
    author='Cafy',
    author_email='cafy-support@cisco.com',
    version=__version__,
    license="GPLv2",
    url='https://github.com/kuamrend/cafy-pytest',
    description='Pytest Cafy Plugin', 	
    install_requires=['pytest>=2.3', 'jinja2'],
    # the following makes a plugin available to pytest
    entry_points={
        'pytest11': ['cafy_pytest = cafy_pytest.plugin']
    },
    # custom PyPI classifier for pytest plugins
    classifiers=[
        "Framework :: Pytest",
    ],
)
