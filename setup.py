from setuptools import setup, find_packages


version = '0.1.0'
name='wswebserver'

setup(
    name=name,
    version=version,
    description='WsWebServer.',
    long_description='A websocket proxy and web app server.',
    packages=['wswebserver', 'wswebserver.util', 'fronwswebserver'],
    scripts=['fronwebsockify'],
    #data_files=[
    #    ('etc/websockify', ['etc/websockify/websockify', 'etc/websockify/passwds', 'etc/websockify/tokens']),
    #    ('etc/rc.d/init.d', ['fronwebsockifyd'])
    #],
    zip_safe=False,
    include_package_data=True
)
