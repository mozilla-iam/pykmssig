from distutils.core import setup

setup(name="pykmssig",
      version="0.0.5",
      author="Andrew Krug",
      author_email="andrewkrug@gmail.com",
      packages=["pykmssig"],
      license="MPL",
      description="pykmssig is a utility for signing and verifying files on AWS using the Key Management Service",
      url='https://github.com/andrewkrug/pykmssig',
      download_url="",
      install_requires=[
        'boto3',
        'cryptography',
        'python-decouple',
        'aws-encryption-sdk',
        'pyblake2'
      ]
  )
