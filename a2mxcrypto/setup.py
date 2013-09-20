from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
 
setup(ext_modules=[Extension("a2mxcrypto", ["a2mxcryptopy.pyx", "a2mxcrypto.cpp", "crypto.cpp", "a2mxpow.cpp"], language="c++", extra_objects=["libcryptopp.a"], extra_compile_args = ['-std=c++11'],)],
cmdclass = {'build_ext': build_ext})
