import os


def get_version_from_file():

    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "VERSION")

    with open(filename, "r") as f:
        version = f.readline()

    return version
