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

VERSION = "1.1.14"

requirements = [
    'confidant-common=={0}'.format(VERSION),

    # Boto3 is the Amazon Web Services (AWS) Software Development Kit (SDK)
    # for Python.
    # License: Apache2
    # Upstream url: https://github.com/boto/boto3
    # Use: For KMS
    'boto3>=1.2.0,<1.4.0',

    # cryptography is a package which provides cryptographic recipes and
    # primitives to Python developers.
    # License: BSD
    # Upstream url: https://github.com/pyca/cryptography
    # Use: For encryption
    'cryptography>=1.2.1,<1.3.0',

    # Python HTTP for Humans.
    # License: Apache2
    # Upstream url: http://python-requests.org
    # Use: REST calls to external services
    'requests>=2.9.1,<2.10.0',

    # Provides enhanced HTTPS support for httplib and urllib2 using PyOpenSSL
    # License: BSD
    # Upstream url: https://github.com/cedadev/ndg_httpsclient/
    # Use: Securing requests for python < 2.7.9.
    'ndg-httpsclient>=0.4.0,<0.5.0',

    # ASN.1 types and codecs
    # License: BSD
    # Upstream url: http://sourceforge.net/projects/pyasn1/
    # Use: Securing requests for python < 2.7.9.
    'pyasn1>=0.1.9,<0.2.0',

    # Python wrapper module around the OpenSSL library
    # License: APL2
    # Upstream url: https://github.com/pyca/pyopenssl
    # Use: Securing requests for python < 2.7.9.
    'pyOpenSSL>=0.15.1,<0.16.0',

    # License: MIT
    # Upstream url: http://pyyaml.org/wiki/PyYAML
    # Use: For parsing users.yaml
    'PyYAML>=3.11'
]

setup(
    name="confidant-client",
    version=VERSION,
    install_requires=requirements,
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
