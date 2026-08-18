from setuptools import find_packages, setup

setup(
    name="caseds",
    version="1.0.0",
    description="CASEDS threat detection system",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=1.10,<2.0",
        "transformers>=4.44.0",
    ],
)
