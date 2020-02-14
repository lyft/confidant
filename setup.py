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

from setuptools import setup, find_packages

with open('requirements.in') as f:
    reqs = f.read().splitlines()

with open('VERSION') as f:
    VERSION = f.read()

setup(
    name="confidant",
    version=VERSION,
    packages=find_packages(exclude=["test*"]),
    include_package_data=True,
    zip_safe=False,
    install_requires=reqs,
    author="Ryan Lane",
    author_email="rlane@lyft.com",
    description="A secret management system and client.",
    license="apache2",
    url="https://github.com/lyft/confidant",
    entry_points={
        'console_scripts': [
            'confidant-admin = confidant.scripts.manage:main',
        ]
    }
)
