from setuptools import setup

setup(name='rtorrent_event',
      version='0.1',
      description="act on rtorrent events as reflected in session directory",
      author='lostnihilist',
      author_email='lostnihilist@gmail.com',
      install_requires=['inotify',],
      keywords='rtorrent',
      scripts=['bin/rtorrent_event'],
      packages=['rtorrent_event'],
     )
