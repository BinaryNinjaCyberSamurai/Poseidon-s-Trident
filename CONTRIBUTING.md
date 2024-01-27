# Contributing to Poseidon's Trident

Thank you for your interest in contributing to Poseidon's Trident, a triad of cybersecurity - threat detection, protection, and response. We welcome contributions from anyone who wants to improve the security of their network and cloud infrastructure, using cutting-edge techniques and tools.

This document provides some guidelines and best practices for contributing to this project. Please read it carefully before you start working on any issues or pull requests.

## Table of Contents

- Code of Conduct
- Getting Started
- Reporting Issues
- Submitting Pull Requests
- Coding Standards and Conventions
- Testing and Debugging
- Documentation
- Communication
- License

## Code of Conduct

We expect all contributors to follow our Code of Conduct, which outlines the standards of behavior and mutual respect that we uphold in this project. By participating in this project, you agree to abide by its terms. If you witness or experience any unacceptable behavior, please report it to the project maintainers.

## Getting Started

To start contributing to this project, you need to have some prerequisites installed and configured on your machine. These include:

- Python 3.8 or higher
- pip
- git
- virtualenv (optional)

You also need to fork the repository and create your own branch from master. To do that, follow these steps:

1. Fork the repository on GitHub by clicking the "Fork" button on the top right corner of the page.
2. Clone your fork to your local machine using the following command:


git clone https://github.com/<your-username>/Poseidon-s-Trident.git


3. Change your working directory to the cloned repository:


cd Poseidon-s-Trident


4. Create a virtual environment and activate it (optional):


virtualenv venv source venv/bin/activate


5. Install the required packages using pip:


pip install -r requirements.txt


6. Create a new branch from master and switch to it:


git checkout -b <your-branch-name>


Now you are ready to work on your issues or pull requests.

## Reporting Issues

If you encounter any bugs, errors, or problems with the project, please report them using the GitHub issue tracker. Before you create a new issue, please check if there is already an existing issue that matches your problem. If not, follow these steps to create a new issue:

1. Go to the Issues page of the repository and click the "New issue" button.
2. Choose a relevant issue template from the list, such as "Bug report" or "Feature request".
3. Fill out the template with as much detail as possible, following the instructions and prompts in the template.
4. Add any relevant labels, such as "bug", "enhancement", or "help wanted".
5. Submit the issue and wait for a response from the project maintainers or other contributors.

Please be respectful and constructive when reporting issues. Provide clear and concise descriptions of the problem, steps to reproduce it, expected and actual results, and any screenshots or logs that can help illustrate the issue. Do not spam, troll, or harass anyone in the issue tracker.

## Submitting Pull Requests

If you want to contribute code or documentation to the project, you need to submit a pull request. A pull request is a request to merge your changes into the main branch of the repository. Before you submit a pull request, please make sure that:

- You have read and followed the Coding Standards and Conventions and the Testing and Debugging sections of this document.
- You have updated the Documentation if your changes affect the user interface or the functionality of the project.
- You have checked that your code passes the tests and does not introduce any new errors or warnings.
- You have rebased your branch on the latest master and resolved any conflicts.

To submit a pull request, follow these steps:

1. Push your changes to your forked repository using the following command:


git push origin <your-branch-name>


2. Go to the Pull requests page of the repository and click the "New pull request" button.
3. Choose your branch as the source branch and the master branch as the base branch, and click the "Create pull request" button.
4. Fill out the pull request template with a clear and concise title and description of your changes, following the instructions and prompts in the template.
5. Add any relevant labels, such as "bugfix", "enhancement", or "documentation".
6. Submit the pull request and wait for a review from the project maintainers or other contributors.

Please be respectful and constructive when submitting pull requests. Provide clear and concise explanations of your changes, the motivation and context behind them, and any references or links that can support your claims. Do not spam, troll, or harass anyone in the pull request tracker.

## Coding Standards and Conventions

We follow the PEP 8 style guide for Python code, and the Google Python Style Guide for docstrings and comments. We use flake8 and pylint to check the code quality and style. We also use black to format the code automatically.

Please make sure that your code follows these standards and conventions before you submit a pull request. You can use the following commands to check and format your code:

- To check the code quality and style using flake8 and pylint:


flake8 . pylint .


- To format the code using black:


black .


Please also use meaningful and descriptive names for your variables, functions, classes, and modules. Avoid using single-letter names, abbreviations, or acronyms that are not widely known or understood. Use comments and docstrings to explain the purpose and logic of your code, following the Google Python Style Guide conventions.

## Testing and Debugging

We use pytest and coverage to test and measure the code coverage of the project. We also use tox to run the tests and checks in different environments.

Please make sure that your code passes the tests and does not introduce any new errors or warnings before you submit a pull request. You can use the following commands to run the tests and checks:

- To run the tests using pytest:


pytest


- To measure the code coverage using coverage:


coverage run -m pytest coverage report


- To run the tests and checks in different environments using tox:


tox


Please also write new tests for your code if it adds new functionality or modifies existing functionality. Follow the pytest conventions and best practices for writing tests. Use descriptive and informative names for your test functions and classes, and use comments and docstrings to explain the test cases and expected results.

## Documentation

We use Sphinx and Read the Docs to generate and host the documentation of the project. The documentation is written in reStructuredText format, and follows the Sphinx conventions and best practices.

Please update the documentation if your code affects the user interface or the functionality of the project. You can use the following commands to build and view the documentation locally:

- To build the documentation using Sphinx:


cd docs make html


- To view the documentation using a web browser:


open _build/html/index.html


Please also write clear and concise docstrings and comments for your code, following the [Google Python Style
