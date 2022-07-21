# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     setup
   Description :
   Author :       liaozhaoyan
   date：          2022/1/14
-------------------------------------------------
   Change Activity:
                   2022/1/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

VERSION = '0.7.4'

import sys
from setuptools import setup, find_packages

if sys.version_info.major == 2:
    reqLists = ["certifi==2017.4.17", "pip==20.3.4", "requests"]
else:
    reqLists = ["requests"]

setup(name='surftrace',
      version=VERSION,
      description="surftrace is a tool that allows you to surf the linux kernel.",
      long_description='surftrace is a tool that allows you to surf the linux kernel.',
      classifiers=["Topic :: System :: Operating System Kernels :: Linux",
                   "Programming Language :: Python",
                   "Programming Language :: Python :: 2",
                   "Programming Language :: Python :: 2.7",
                   "Programming Language :: Python :: 3",
                   "Programming Language :: Python :: 3.5",
                   "Programming Language :: Python :: 3.6",
                   "Programming Language :: Python :: 3.7",
                   "Programming Language :: Python :: 3.8",
                   "Programming Language :: Python :: 3.9",
                   "Programming Language :: Python :: 3.10",
                   "Programming Language :: Python :: Implementation :: PyPy",
                   ],  # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='linux kernel trace',
      author='liaozhaoyan',
      author_email='zhaoyan.liao@linux.alibaba.com',
      url="https://gitee.com/anolis/surftrace",
      license='MIT',
      packages=["surftrace"],
      include_package_data=True,
      zip_safe=True,
      install_requires=reqLists,
      entry_points={
          'console_scripts': [
              "surftrace = surftrace.surftrace:main",
              "kobuild = surftrace.kobuild:main",
          ]
      }
      )

if __name__ == "__main__":
    pass
