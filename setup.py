import setuptools

setuptools.setup(
    name="pillar",
    use_scm_version=True,
    setup_requires=['setuptools_scm'],
    packages=setuptools.find_packages(),
    license='GPL V3',
    long_description=open('README.md').read()
)