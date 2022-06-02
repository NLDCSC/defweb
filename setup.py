import os

from setuptools import setup, find_packages

from defweb import _version_from_git_describe

# The directory containing this file
HERE = os.path.abspath(os.path.dirname(__file__))

# The text of the README file
with open(os.path.join(HERE, "README.md")) as fid:
    README = fid.read()

with open(os.path.join(HERE, "requirements.txt")) as fid:
    REQS = fid.read().splitlines()


setup(
    name="defweb",
    version=_version_from_git_describe(),
    packages=find_packages(exclude=("tests",)),
    url="",
    license="GNU General Public License v3.0",
    author="Paul Tikken",
    author_email="paul.tikken@gmail.com",
    description="Python webserver with https and upload support",
    long_description=README,
    long_description_content_type="text/markdown",
    package_data={"defweb": ["LICENSE", "VERSION", "sources/user_agents.txt"]},
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
    ],
    python_requires=">=3.8",
    entry_points={"console_scripts": ["defweb=defweb.__main__:main"]},
    install_requires=REQS,
)
