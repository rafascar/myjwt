from setuptools import setup

setup(
    name='myjwt',
    version='0.1',
    py_modules=['myjwt'],
    install_requires=[
        'pyjwt',
        'cryptography',
        'click',
        'pyperclip'
    ],
    entry_points='''
        [console_scripts]
        myjwt=myjwt:cli
    ''',
)
