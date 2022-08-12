from setuptools import setup
from pybind11.setup_helpers import Pybind11Extension, build_ext

ext_modules = [
    Pybind11Extension(
        "pybypasscore",
        ["pybypasscore.cpp"],
        include_dirs=["../../include"],
        define_macros=[("_CRT_SECURE_NO_WARNINGS", "1")],
    ),
]

setup(
    name="pybypasscore",
    version="1.0.0",
    author="BypassCore Labs",
    description="Python bindings for the BypassCore SDK",
    ext_modules=ext_modules,
    cmdclass={"build_ext": build_ext},
    python_requires=">=3.7",
    install_requires=["pybind11>=2.10"],
)
