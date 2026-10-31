import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as f:
    required = f.read().splitlines()

about = {}
with open("tnscm/_version.py") as f:
    exec(f.read(), about)

setuptools.setup(
    name="tnscm",
    version=about["__version__"],
    license="MIT",
    author="Damian Krawczyk",
    author_email="damian.krawczyk@limberduck.org",
    description="LimberDuck TNSCM - CLI Manager for Tenable Nessus",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LimberDuck/tnscm",
    packages=setuptools.find_packages(),
    install_requires=required,
    entry_points={"console_scripts": ["tnscm = tnscm.__main__:main"]},
    classifiers=[
        "Programming Language :: Python :: 3.15",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Environment :: Console",
    ],
)
