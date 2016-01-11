# pylint: disable=missing-docstring
# Copyright (c) 2015 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from setuptools import setup, find_packages
from tap import __version__

setup(
    name='TrustedAnalyticsPlatform',
    version=__version__,
    packages=find_packages(),
    install_requires=[
        'troposphere==1.4.0',
        'awacs==0.5.3',
        'semantic-version==2.4.2',
        'click==6.2',
        ],
    author='Maciej Strzelecki',
    author_email='maciej.strzelecki@intel.com',
    license='Apache License, Version 2.0',
    url='https://trustedanalytics.github.io/',
    entry_points={
        'console_scripts': [
            'tap = tap.cli:cli',
            ],
        },
)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 colorcolumn=100
