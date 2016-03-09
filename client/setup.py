# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup
from pip.req import parse_requirements
from pip.exceptions import InstallationError

VERSION = "1.1.5"

try:
    client_reqs = parse_requirements(
        "requirements_client.txt",
        session=False
    )
    reqs = [str(ir.req) for ir in client_reqs]
except InstallationError:
    client_reqs = parse_requirements(
        "client/requirements_client.txt",
        session=False
    )
    reqs = [str(ir.req) for ir in client_reqs]
reqs.append('confidant-common=={0}'.format(VERSION))

setup(
    name="confidant-client",
    version=VERSION,
    install_requires=reqs,
    author="Ryan Lane",
    author_email="rlane@lyft.com",
    description="A client for confidant, a secret management system.",
    license="apache2",
    url="https://github.com/lyft/confidant",
    entry_points={
        "console_scripts": [
            "confidant = confidant.cli:main",
            "confidant-format = confidant.formatter:main"
        ],
    },
)
