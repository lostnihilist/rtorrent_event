from setuptools import setup
import sys

if sys.version_info < (3, 5):
    sys.exit("Requires Python 3.5+.")

setup(name='rtorrent_event',
      version='0.2',
      description="act on rtorrent events as reflected in session directory",
      author='lostnihilist',
      author_email='lostnihilist@gmail.com',
      install_requires=['inotify',
                        'bencode @ https://github.com/fuzeman/bencode.py.git',
                        'daemons @ https://github.com/kevinconway/daemons.git'],
      keywords='rtorrent',
      scripts=['bin/rtorrent_event', 'bin/rtorrent_watch'],
      packages=['rtorrent_event'],
     )

