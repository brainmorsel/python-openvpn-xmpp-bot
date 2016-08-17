from setuptools import setup, find_packages

setup(
    name='openvpn-xmpp-bot',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'click==6.6',
        'sleekxmpp==1.3.1',
        'dnspython3==1.12.0',
    ],
    entry_points='''
        [console_scripts]
        openvpn-xmpp-bot=app.main:cli
    ''',
    )
