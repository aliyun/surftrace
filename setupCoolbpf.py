# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     setupCoolbpf
   Description :
   Author :       liaozhaoyan
   date：          2022/6/14
-------------------------------------------------
   Change Activity:
                   2022/6/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

VERSION = '0.1.1'

from setuptools import setup

setup(name='coolbpf',
      version=VERSION,
      description="cool libbpf compile collections",
      long_description='cool libbpf compile collections.',
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
      url="https://github.com/aliyun/coolbpf",
      license='MIT',
      packages=["coolbpf"],
      include_package_data=True,
      zip_safe=True,
      install_requires=['surftrace>=0.7.3', "pylcc>=0.2.9"],
      entry_points={
          'console_scripts': [
              "coolbpf = coolbpf.coolbpf:main",
          ]
      }
      )

if __name__ == "__main__":
    pass

