# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     setupPylcc
   Description :
   Author :       liaozhaoyan
   date：          2022/1/17
-------------------------------------------------
   Change Activity:
                   2022/1/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

VERSION = '0.1'

from setuptools import setup, find_packages

setup(name='pylcc',
      version=VERSION,
      description="pylcc is short for python libbpf compile collections",
      long_description='pylcc is short for python libbpf compile collections',
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
                   "Programming Language :: Python :: Implementation :: PyPy",
                   ],  # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='linux kernel trace',
      author='liaozhaoyan',
      author_email='zhoayan.liao@linux.alibaba.com',
      url="https://github.com/aliyun/surftrace",
      license='MIT',
      packages=["pylcc"],
      include_package_data=True,
      zip_safe=True,
      install_requires=['surftrace>=0.1'],
      )

if __name__ == "__main__":
    pass
